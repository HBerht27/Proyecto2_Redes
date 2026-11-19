"""Servidor TCP del protocolo BOVEDA-1."""

from __future__ import annotations

import json
import os
import socket
import threading

from pathlib import Path

from common import criptografia, framing, mensaje
from common.mensaje import construir, parsear
from common.tipos import (
    DIR_CLIENTE_SERVIDOR,
    DIR_SERVIDOR_CLIENTE,
    HELLO,
    WELCOME,
    LOGIN,
    LOGIN_OK,
    LOGIN_ERR,
    ERROR,
    CIERRE,
    RESP,
    PUERTO_ASILO,
)

from servidor.almacen import Almacen
from servidor.perfiles import Custodio, cargar
from servidor.sesiones import Sesion, procesar_login
from servidor.comandos import manejar_comando


_NS_SERVIDOR = os.urandom(16)


class ErrorProtocolo(Exception):
    pass


def _atender_handshake(sock: socket.socket) -> tuple[bytes, str]:
    datos = framing.recibir(sock)
    msg = parsear(datos)

    if msg.tipo != HELLO or msg.dir != DIR_CLIENTE_SERVIDOR:
        raise ErrorProtocolo("HELLO invalido")

    if msg.seq != 0 or msg.iv != bytes(12) or msg.hmac is not None:
        raise ErrorProtocolo("Formato de HELLO invalido")

    cuerpo = json.loads(msg.cuerpo)

    if not isinstance(cuerpo, dict):
        raise ErrorProtocolo("Cuerpo invalido")

    usuario = cuerpo.get("usuario")
    nc_hex = cuerpo.get("nc")

    if not isinstance(usuario, str) or not isinstance(nc_hex, str):
        raise ErrorProtocolo("Datos de handshake invalidos")

    nc = bytes.fromhex(nc_hex)

    if len(nc) != 16:
        raise ErrorProtocolo("Nonce invalido")

    respuesta = json.dumps({
        "ns": _NS_SERVIDOR.hex()
    }).encode("utf-8")

    paquete = construir(
        WELCOME,
        DIR_SERVIDOR_CLIENTE,
        0,
        bytes(12),
        respuesta
    )

    framing.enviar(sock, paquete)

    return nc, usuario


def _recibir_cifrado(sock: socket.socket, sesion: Sesion):
    datos = framing.recibir(sock)
    msg = parsear(datos)

    if msg.dir != DIR_CLIENTE_SERVIDOR:
        raise ErrorProtocolo("Direccion invalida")

    if msg.hmac is None:
        raise ErrorProtocolo("Mensaje sin HMAC")

    if not mensaje.verificar(msg, datos, sesion.k_mac):
        raise ErrorProtocolo("HMAC invalido")

    if not sesion.seq_cliente_valido(msg.seq):
        raise ErrorProtocolo("Secuencia invalida")

    claro = criptografia.descifrar(
        msg.cuerpo,
        sesion.k_enc,
        msg.iv
    )

    cuerpo = json.loads(claro)

    if not isinstance(cuerpo, dict):
        raise ErrorProtocolo("Cuerpo invalido")

    return msg.tipo, cuerpo


def _enviar_cifrado(
    sock: socket.socket,
    sesion: Sesion,
    tipo: int,
    cuerpo: dict
) -> None:

    iv = os.urandom(12)

    claro = json.dumps(cuerpo).encode("utf-8")

    cifrado = criptografia.cifrar(
        claro,
        sesion.k_enc,
        iv
    )

    paquete = construir(
        tipo,
        DIR_SERVIDOR_CLIENTE,
        sesion.siguiente_seq_servidor(),
        iv,
        cifrado,
        sesion.k_mac
    )

    framing.enviar(sock, paquete)


def manejar_conexion(
    sock: socket.socket,
    direccion,
    perfiles: dict[str, Custodio],
    almacen: Almacen
) -> None:

    sesion = None

    try:
        sock.settimeout(30)

        nc, usuario = _atender_handshake(sock)

        custodio = perfiles.get(usuario)

        if custodio is None:
            return

        k_enc, k_mac = criptografia.derivar_claves_sesion(
            custodio.s_u,
            nc,
            _NS_SERVIDOR
        )

        sesion = Sesion(k_enc, k_mac, nc)

        tipo, cuerpo = _recibir_cifrado(sock, sesion)

        if tipo != LOGIN:
            raise ErrorProtocolo("Se esperaba LOGIN")

        if not procesar_login(custodio, sesion, cuerpo):
            _enviar_cifrado(
                sock,
                sesion,
                LOGIN_ERR,
                {"mensaje": "error"}
            )
            return

        _enviar_cifrado(
            sock,
            sesion,
            LOGIN_OK,
            {"perfil": sesion.perfil}
        )

        while True:
            tipo, cuerpo = _recibir_cifrado(sock, sesion)

            tipo_respuesta, respuesta = manejar_comando(
                tipo,
                almacen,
                sesion,
                cuerpo
            )

            _enviar_cifrado(
                sock,
                sesion,
                tipo_respuesta,
                respuesta
            )

            if tipo == CIERRE and tipo_respuesta == RESP:
                break

    except (
        ErrorProtocolo,
        ValueError,
        TypeError,
        UnicodeError,
        KeyError,
        framing.ConexionCerrada,
        framing.MensajeDemasiadoGrande,
        mensaje.MensajeInvalido,
        socket.timeout,
        OSError
    ):
        if sesion is not None:
            try:
                _enviar_cifrado(
                    sock,
                    sesion,
                    ERROR,
                    {"mensaje": "error"}
                )
            except (OSError, ValueError):
                pass

    finally:
        if sesion is not None:
            sesion.k_enc = b""
            sesion.k_mac = b""

        sock.close()


def main(
    host: str = "0.0.0.0",
    puerto: int = PUERTO_ASILO
) -> None:

    raiz = Path(__file__).resolve().parent.parent

    perfiles = cargar(raiz / "datos" / "perfiles.txt")

    almacen = Almacen()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as servidor:
        servidor.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1
        )

        servidor.bind((host, puerto))
        servidor.listen()

        print(f"Boveda escuchando en {host}:{puerto}")

        while True:
            sock, direccion = servidor.accept()

            print(f"Conexion recibida: {direccion}")

            manejar_conexion(
                sock,
                direccion,
                perfiles,
                almacen
            )


if __name__ == "__main__":
    main()