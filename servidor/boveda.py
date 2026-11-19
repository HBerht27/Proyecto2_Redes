"""Servidor TCP de BOVEDA-1."""
from __future__ import annotations

import json
import os
import socket
import threading
from pathlib import Path

from common import criptografia, framing, mensaje
from common.mensaje import construir, parsear
from common.tipos import (
    DIR_CLIENTE_SERVIDOR, DIR_SERVIDOR_CLIENTE,
    HELLO, WELCOME, LOGIN, LOGIN_OK, LOGIN_ERR,
    ASILO, ASILO_OK, CONSULTAR, AGREGAR, BORRAR,
    CIERRE, RESP, ERROR, PUERTO_ASILO,
)
from servidor.almacen import Almacen
from servidor.perfiles import Custodio, cargar
from servidor.sesiones import Sesion, procesar_login
from servidor.comandos import manejar_comando

_NS_SERVIDOR = os.urandom(16)
MAX_CONEXIONES = 50


class ErrorProtocolo(Exception):
    pass


class EstadoServidor:
    def __init__(self, almacen: Almacen):
        self.almacen = almacen
        self.activo = threading.Event()
        self.activo.set()
        self.lock = threading.Lock()
        self.lugares = threading.BoundedSemaphore(MAX_CONEXIONES)
        self.conexiones = set()
        self.ips_asilo = set()
        self.escucha = None

    def registrar(self, sock):
        with self.lock:
            if not self.activo.is_set():
                return False
            self.conexiones.add(sock)
            return True

    def liberar(self, sock):
        with self.lock:
            self.conexiones.discard(sock)
        self.lugares.release()

    def entrar_asilo(self, ip):
        with self.lock:
            if not self.activo.is_set() or ip in self.ips_asilo:
                return False
            self.ips_asilo.add(ip)
            return True

    def salir_asilo(self, ip):
        with self.lock:
            self.ips_asilo.discard(ip)

    def derrumbar(self):
        with self.lock:
            if not self.activo.is_set():
                return
            self.activo.clear()
            conexiones = list(self.conexiones)
            escucha = self.escucha
        # Primero se impiden operaciones futuras en el almacen.
        self.almacen.derrumbar()
        if escucha is not None:
            try:
                escucha.close()
            except OSError:
                pass
        for sock in conexiones:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def _atender_handshake(sock, primero):
    msg = primero
    if msg.tipo != HELLO or msg.dir != DIR_CLIENTE_SERVIDOR:
        raise ErrorProtocolo("HELLO invalido")
    if msg.seq != 0 or msg.iv != bytes(12) or msg.hmac is not None:
        raise ErrorProtocolo("Formato de HELLO invalido")
    cuerpo = json.loads(msg.cuerpo)
    if not isinstance(cuerpo, dict):
        raise ErrorProtocolo("Cuerpo invalido")
    usuario, nc_hex = cuerpo.get("usuario"), cuerpo.get("nc")
    if not isinstance(usuario, str) or not isinstance(nc_hex, str):
        raise ErrorProtocolo("Handshake invalido")
    nc = bytes.fromhex(nc_hex)
    if len(nc) != 16:
        raise ErrorProtocolo("Nonce invalido")
    respuesta = json.dumps({"ns": _NS_SERVIDOR.hex()}).encode("utf-8")
    framing.enviar(sock, construir(WELCOME, DIR_SERVIDOR_CLIENTE, 0, bytes(12), respuesta))
    return nc, usuario


def _recibir_cifrado(sock, sesion):
    datos = framing.recibir(sock)
    msg = parsear(datos)
    if msg.dir != DIR_CLIENTE_SERVIDOR or msg.hmac is None:
        raise ErrorProtocolo("Mensaje invalido")
    if not mensaje.verificar(msg, datos, sesion.k_mac):
        raise ErrorProtocolo("HMAC invalido")
    if not sesion.seq_cliente_valido(msg.seq):
        raise ErrorProtocolo("Secuencia invalida")
    claro = criptografia.descifrar(msg.cuerpo, sesion.k_enc, msg.iv)
    cuerpo = json.loads(claro)
    if not isinstance(cuerpo, dict):
        raise ErrorProtocolo("Cuerpo invalido")
    return msg.tipo, cuerpo


def _enviar_cifrado(sock, sesion, tipo, cuerpo):
    iv = os.urandom(12)
    claro = json.dumps(cuerpo).encode("utf-8")
    cifrado = criptografia.cifrar(claro, sesion.k_enc, iv)
    paquete = construir(tipo, DIR_SERVIDOR_CLIENTE,
                        sesion.siguiente_seq_servidor(), iv, cifrado, sesion.k_mac)
    framing.enviar(sock, paquete)


def _enviar_asilo(sock, tipo, cuerpo):
    contenido = json.dumps(cuerpo).encode("utf-8")
    # ASILO_OK usa el formato publico sin HMAC.
    framing.enviar(sock, construir(tipo, DIR_SERVIDOR_CLIENTE, 0, bytes(12), contenido))


def _atender_asilo(sock, ip, estado, primero):
    if primero.dir != DIR_CLIENTE_SERVIDOR or primero.seq != 0 or primero.iv != bytes(12):
        raise ErrorProtocolo("ASILO invalido")
    cuerpo = json.loads(primero.cuerpo)
    if not isinstance(cuerpo, dict) or not all(
        isinstance(cuerpo.get(k), str) and cuerpo[k].strip()
        for k in ("peticion", "sal", "harina")
    ):
        raise ErrorProtocolo("Solicitud de asilo invalida")
    if not estado.entrar_asilo(ip):
        return
    try:
        _enviar_asilo(sock, ASILO_OK, {"perfil": "hacinado"})
        while estado.activo.is_set():
            datos = framing.recibir(sock)
            peticion = parsear(datos)
            # Una sesion hacinado no tiene claves y no ejecuta comandos.
            if peticion.tipo in (CONSULTAR, AGREGAR, BORRAR, CIERRE):
                # ERROR requiere HMAC segun el formato compartido.
                # En asilo no hay secreto compartido, por lo que cerramos
                # esta conexion sin ejecutar la solicitud.
                return
            return
    finally:
        estado.salir_asilo(ip)


def manejar_conexion(sock, direccion, perfiles, almacen, estado):
    sesion = None
    try:
        sock.settimeout(30)
        primero = parsear(framing.recibir(sock))
        if primero.tipo == ASILO:
            _atender_asilo(sock, direccion[0], estado, primero)
            return
        nc, usuario = _atender_handshake(sock, primero)
        custodio = perfiles.get(usuario)
        if custodio is None:
            return
        k_enc, k_mac = criptografia.derivar_claves_sesion(custodio.s_u, nc, _NS_SERVIDOR)
        sesion = Sesion(k_enc, k_mac, nc)
        tipo, cuerpo = _recibir_cifrado(sock, sesion)
        if tipo != LOGIN:
            raise ErrorProtocolo("Se esperaba LOGIN")
        if not procesar_login(custodio, sesion, cuerpo):
            _enviar_cifrado(sock, sesion, LOGIN_ERR, {"mensaje": "error"})
            return
        _enviar_cifrado(sock, sesion, LOGIN_OK, {"perfil": sesion.perfil})
        while estado.activo.is_set():
            tipo, cuerpo = _recibir_cifrado(sock, sesion)
            if not estado.activo.is_set():
                return
            tipo_respuesta, respuesta = manejar_comando(tipo, almacen, sesion, cuerpo)
            _enviar_cifrado(sock, sesion, tipo_respuesta, respuesta)
            if tipo == CIERRE and tipo_respuesta == RESP:
                estado.derrumbar()
                return
    except (ErrorProtocolo, ValueError, TypeError, UnicodeError, KeyError,
            framing.ConexionCerrada, framing.MensajeDemasiadoGrande,
            mensaje.MensajeInvalido, socket.timeout, OSError):
        if sesion is not None and estado.activo.is_set():
            try:
                _enviar_cifrado(sock, sesion, ERROR, {"mensaje": "error"})
            except (OSError, ValueError):
                pass
    finally:
        if sesion is not None:
            sesion.k_enc = b""
            sesion.k_mac = b""
        try:
            sock.close()
        finally:
            estado.liberar(sock)


def main(host="0.0.0.0", puerto=PUERTO_ASILO):
    raiz = Path(__file__).resolve().parent.parent
    perfiles = cargar(raiz / "datos" / "perfiles.txt")
    almacen = Almacen()
    estado = EstadoServidor(almacen)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as servidor:
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        servidor.bind((host, puerto))
        servidor.listen(MAX_CONEXIONES)
        servidor.settimeout(1)
        estado.escucha = servidor
        print(f"Boveda escuchando en {host}:{puerto}")
        try:
            while estado.activo.is_set():
                try:
                    sock, direccion = servidor.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if not estado.activo.is_set():
                        break
                    raise
                if not estado.lugares.acquire(blocking=False):
                    sock.close()
                    continue
                if not estado.registrar(sock):
                    sock.close()
                    estado.lugares.release()
                    continue
                hilo = threading.Thread(
                    target=manejar_conexion,
                    args=(sock, direccion, perfiles, almacen, estado),
                    daemon=True
                )
                hilo.start()
        except KeyboardInterrupt:
            print("Servidor detenido")
        finally:
            if estado.activo.is_set():
                estado.activo.clear()
                for sock in list(estado.conexiones):
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass


if __name__ == "__main__":
    main()
