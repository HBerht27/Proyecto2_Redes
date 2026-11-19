"""Cliente de BOVEDA-1 (el custodio): handshake, LOGIN, comandos por
CLI, y solicitud de asilo.

Usa common/ (framing, mensaje, criptografia) igual que el servidor; aqui
no se duplica esa logica.

Flujo de conectar() + login():
    1. Socket TCP contra (host, puerto).
    2. HELLO con {"usuario", "nc"} -- nc nuevo en cada conexion, en
       claro, sin HMAC.
    3. WELCOME -> "ns".
    4. derivar_claves_sesion(s_u, nc, ns) -> (k_enc, k_mac).
    5. LOGIN cifrado: {"usuario", "perfil", "prueba"}, con
       prueba = HMAC-SHA256(s_u, b"LOGIN" + usuario + nc) en hex.
    6. LOGIN_OK o LOGIN_ERR.

Despues, cada comando es un mensaje cifrado con k_enc, iv nuevo
(os.urandom(12)), HMAC con k_mac y seq propio creciente. Cada respuesta
se valida en este orden: direccion, HMAC, seq estrictamente mayor que la
ultima respuesta aceptada, y solo entonces se descifra.

Numeracion de seq del cliente: el LOGIN usa seq=1 y los comandos siguen
2, 3, ... Asi funciona tanto si el servidor cuenta el LOGIN como si no
(sesiones.py exige seq estrictamente mayor al ultimo visto).

Cuerpos de los comandos (JSON, antes de cifrar):
    CONSULTAR {"clave"}   AGREGAR {"clave", "valor"}
    BORRAR    {"clave"}   CIERRE  {}
Las respuestas se devuelven como dict con el cuerpo descifrado mas la
llave "_tipo" ("RESP" o "ERROR").
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import socket
import sys
from pathlib import Path

from common import criptografia, framing, mensaje
from common.tipos import (
    AGREGAR,
    ASILO,
    ASILO_OK,
    BORRAR,
    CIERRE,
    CONSULTAR,
    DIR_CLIENTE_SERVIDOR,
    DIR_SERVIDOR_CLIENTE,
    ERROR,
    HELLO,
    LOGIN,
    LOGIN_ERR,
    LOGIN_OK,
    NOMBRES,
    PERFIL_INTEGRANTE,
    PERFILES_VALIDOS,
    PUERTO_ASILO,
    RESP,
    WELCOME,
)

try:  # solo para leer datos/perfiles.txt cuando se corre en la misma maquina
    from servidor import perfiles as _perfiles
except ImportError:  # el cliente tambien debe funcionar sin el paquete servidor
    _perfiles = None

_TAM_NS = 16
_MAX_CUERPO = 0xFFFF  # plen son 2 bytes en la cabecera
_RUTA_PERFILES = Path(__file__).resolve().parent.parent / "datos" / "perfiles.txt"


class ErrorProtocolo(Exception):
    """Algo salio mal en la conversacion con la Boveda (red, formato, HMAC,
    seq repetido, respuesta inesperada)."""


class ConexionPerdida(ErrorProtocolo):
    """La Boveda cerro la conexion."""


def generar_nc() -> bytes:
    """nc: nonce del cliente para el handshake, 16 bytes.

    Sale de os.urandom (fuente criptografica del SO) y se genera uno
    NUEVO en cada conectar(). random.getrandbits es predecible y, si nc
    se reutilizara entre conexiones, dos sesiones del mismo custodio
    compartirian claves de sesion y numeros de secuencia.
    """
    return os.urandom(_TAM_NS)


def _nombre(tipo: int) -> str:
    return NOMBRES.get(tipo, f"0x{tipo:02x}")


def _json_claro(cuerpo: bytes) -> dict:
    try:
        datos = json.loads(cuerpo) if cuerpo else {}
    except ValueError:
        return {}
    return datos if isinstance(datos, dict) else {}


class Custodio:
    def __init__(self, host: str, puerto: int, usuario: str, perfil: str, s_u: bytes,
                 timeout: float = 10.0) -> None:
        self.host = host
        self.puerto = puerto
        self.usuario = usuario
        self.perfil = perfil
        self._s_u = s_u
        self._timeout = timeout

        self._sock: socket.socket | None = None
        self._nc: bytes | None = None
        self._k_enc: bytes | None = None
        self._k_mac: bytes | None = None
        self._seq_propio = 0
        self._seq_servidor_visto = -1  # acepta cualquier seq >= 0 la primera vez
        self._autenticado = False

    # ---------- ciclo de vida ----------

    @property
    def conectado(self) -> bool:
        return self._sock is not None

    def __enter__(self) -> "Custodio":
        return self

    def __exit__(self, *_exc) -> None:
        self.cerrar()

    def cerrar(self) -> None:
        sock, self._sock = self._sock, None
        self._k_enc = self._k_mac = self._nc = None
        self._autenticado = False
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    # ---------- E/S de bajo nivel ----------

    def _enviar_crudo(self, datos: bytes) -> None:
        if self._sock is None:
            raise ErrorProtocolo("no hay conexion abierta")
        try:
            framing.enviar(self._sock, datos)
        except OSError as e:
            raise ConexionPerdida(f"no se pudo enviar: {e}") from e

    def _leer(self) -> tuple[mensaje.Mensaje, bytes]:
        if self._sock is None:
            raise ErrorProtocolo("no hay conexion abierta")
        try:
            datos = framing.recibir(self._sock)
            return mensaje.parsear(datos), datos
        except framing.ConexionCerrada as e:
            raise ConexionPerdida(str(e)) from e
        except (framing.MensajeDemasiadoGrande, mensaje.MensajeInvalido) as e:
            raise ErrorProtocolo(f"mensaje invalido del servidor: {e}") from e
        except OSError as e:  # incluye timeout
            raise ConexionPerdida(f"error de red: {e}") from e

    def _enviar_cifrado(self, tipo: int, cuerpo: dict) -> None:
        if self._k_enc is None or self._k_mac is None:
            raise ErrorProtocolo("todavia no hay clave de sesion")
        iv = os.urandom(12)
        claro = json.dumps(cuerpo, separators=(",", ":")).encode("utf-8")
        cifrado = criptografia.cifrar(claro, self._k_enc, iv)
        if len(cifrado) > _MAX_CUERPO:
            raise ValueError("el cuerpo del mensaje es demasiado grande")
        self._seq_propio += 1
        self._enviar_crudo(mensaje.construir(
            tipo, DIR_CLIENTE_SERVIDOR, self._seq_propio, iv, cifrado, self._k_mac))

    def _validar_respuesta(self, msg: mensaje.Mensaje, datos: bytes) -> dict:
        """Direccion -> HMAC -> seq -> descifrar. Nunca se avanza el seq ni
        se descifra algo que no paso el HMAC."""
        if self._k_enc is None or self._k_mac is None:
            raise ErrorProtocolo("todavia no hay clave de sesion")
        if msg.dir != DIR_SERVIDOR_CLIENTE:
            raise ErrorProtocolo("el mensaje no viene en direccion servidor->cliente")
        try:
            hmac_ok = mensaje.verificar(msg, datos, self._k_mac)
        except mensaje.MensajeInvalido as e:
            raise ErrorProtocolo(f"respuesta sin HMAC: {e}") from e
        if not hmac_ok:
            raise ErrorProtocolo("HMAC invalido: la respuesta fue alterada o no es de la Boveda")
        if msg.seq <= self._seq_servidor_visto:
            raise ErrorProtocolo("seq repetido o atrasado: posible repeticion de una respuesta")
        self._seq_servidor_visto = msg.seq

        claro = criptografia.descifrar(msg.cuerpo, self._k_enc, msg.iv)
        try:
            cuerpo = json.loads(claro) if claro else {}
        except ValueError as e:
            raise ErrorProtocolo(f"cuerpo de la respuesta no es JSON: {e}") from e
        if not isinstance(cuerpo, dict):
            raise ErrorProtocolo("el cuerpo de la respuesta no es un objeto JSON")
        return cuerpo

    # ---------- protocolo ----------

    def conectar(self) -> None:
        """Abre el socket, manda HELLO, lee WELCOME y deriva las claves."""
        if self._sock is not None:
            raise ErrorProtocolo("ya hay una conexion abierta")
        try:
            self._sock = socket.create_connection((self.host, self.puerto), timeout=self._timeout)
        except OSError as e:
            raise ErrorProtocolo(f"no se pudo conectar a {self.host}:{self.puerto}: {e}") from e

        try:
            nc = generar_nc()
            hello = json.dumps({"usuario": self.usuario, "nc": nc.hex()}).encode("utf-8")
            self._enviar_crudo(mensaje.construir(HELLO, DIR_CLIENTE_SERVIDOR, 0, bytes(12), hello))

            msg, _ = self._leer()
            if msg.tipo != WELCOME or msg.dir != DIR_SERVIDOR_CLIENTE:
                raise ErrorProtocolo(f"se esperaba WELCOME y llego {_nombre(msg.tipo)}")
            try:
                ns = bytes.fromhex(json.loads(msg.cuerpo)["ns"])
            except (ValueError, KeyError, TypeError) as e:
                raise ErrorProtocolo("WELCOME mal formado") from e
            if len(ns) != _TAM_NS:
                raise ErrorProtocolo(f"ns debe tener {_TAM_NS} bytes")

            self._nc = nc
            self._k_enc, self._k_mac = criptografia.derivar_claves_sesion(self._s_u, nc, ns)
            self._seq_propio = 0
            self._seq_servidor_visto = -1
        except Exception:
            self.cerrar()
            raise

    def login(self) -> bool:
        """True si la Boveda responde LOGIN_OK. False si responde LOGIN_ERR o
        ERROR, o si corta la conexion sin responder."""
        if self._sock is None or self._nc is None:
            raise ErrorProtocolo("hay que llamar a conectar() antes de login()")
        prueba = criptografia.calcular_hmac(
            self._s_u, b"LOGIN" + self.usuario.encode("utf-8") + self._nc).hex()
        self._enviar_cifrado(LOGIN, {"usuario": self.usuario, "perfil": self.perfil, "prueba": prueba})

        try:
            msg, datos = self._leer()
        except ConexionPerdida as e:
            # Con un S_u equivocado el servidor no puede verificar el LOGIN y
            # puede cortar la conexion sin responder: eso es un rechazo.
            # Un timeout u otro error de red si se propaga como error.
            if isinstance(e.__cause__, framing.ConexionCerrada):
                self.cerrar()
                return False
            raise
        if msg.tipo in (LOGIN_ERR, ERROR):
            self._autenticado = False
            return False
        if msg.tipo != LOGIN_OK:
            raise ErrorProtocolo(f"se esperaba LOGIN_OK/LOGIN_ERR y llego {_nombre(msg.tipo)}")
        self._validar_respuesta(msg, datos)
        self._autenticado = True
        return True

    def _comando(self, tipo: int, cuerpo: dict) -> dict:
        if not self._autenticado:
            raise ErrorProtocolo("hay que iniciar sesion antes de enviar comandos")
        self._enviar_cifrado(tipo, cuerpo)
        msg, datos = self._leer()
        resp = self._validar_respuesta(msg, datos)
        if msg.tipo not in (RESP, ERROR):
            raise ErrorProtocolo(f"se esperaba RESP/ERROR y llego {_nombre(msg.tipo)}")
        resp["_tipo"] = _nombre(msg.tipo)
        return resp

    def consultar(self, clave: str) -> dict:
        return self._comando(CONSULTAR, {"clave": clave})

    def agregar(self, clave: str, valor: str) -> dict:
        return self._comando(AGREGAR, {"clave": clave, "valor": valor})

    def borrar(self, clave: str) -> dict:
        return self._comando(BORRAR, {"clave": clave})

    def cierre(self) -> dict:
        """Cierre de emergencia. Si la Boveda se derrumba, puede cerrar el
        socket sin alcanzar a responder: se informa como CONEXION_CERRADA."""
        try:
            resp = self._comando(CIERRE, {})
        except ConexionPerdida:
            self.cerrar()
            return {"_tipo": "CONEXION_CERRADA"}
        if resp["_tipo"] == "RESP":
            self.cerrar()
        return resp


def pedir_asilo(host: str, puerto: int, peticion: str, sal: str, harina: str,
                timeout: float = 10.0) -> dict:
    """ASILO/ASILO_OK: sin clave de sesion, cuerpo en claro, sin HMAC.
    Util para probar el camino de "hacinado" que vera la Casa rival."""
    cuerpo = json.dumps({"peticion": peticion, "sal": sal, "harina": harina}).encode("utf-8")
    try:
        with socket.create_connection((host, puerto), timeout=timeout) as sock:
            framing.enviar(sock, mensaje.construir(ASILO, DIR_CLIENTE_SERVIDOR, 0, bytes(12), cuerpo))
            msg = mensaje.parsear(framing.recibir(sock))
    except (framing.ConexionCerrada, framing.MensajeDemasiadoGrande, mensaje.MensajeInvalido) as e:
        raise ErrorProtocolo(f"asilo: {e}") from e
    except OSError as e:
        raise ErrorProtocolo(f"asilo: error de red: {e}") from e

    resp = _json_claro(msg.cuerpo)
    resp["_tipo"] = _nombre(msg.tipo)
    if msg.tipo not in (ASILO_OK, ERROR):
        raise ErrorProtocolo(f"se esperaba ASILO_OK y llego {_nombre(msg.tipo)}")
    return resp


# ---------- CLI ----------

_AYUDA = """Comandos:
  consultar <clave>
  agregar <clave> <valor...>
  borrar <clave>            (solo jefe)
  cierre                    (solo jefe; derrumba la Boveda)
  ayuda
  salir"""


def _mostrar(resp: dict) -> None:
    tipo = resp.get("_tipo")
    resto = {k: v for k, v in resp.items() if k != "_tipo"}
    texto = json.dumps(resto, ensure_ascii=False)
    print(f"ERROR: {texto}" if tipo == "ERROR" else texto if tipo == "RESP" else f"[{tipo}] {texto}")


def _credenciales(args: argparse.Namespace) -> tuple[bytes, str]:
    """S_u y perfil: de --s-u, o de datos/perfiles.txt si esta a mano, o
    pidiendolo sin eco por teclado."""
    s_u_hex = args.s_u
    perfil = args.perfil
    if s_u_hex is None and _perfiles is not None and Path(args.perfiles).exists():
        try:
            custodio = _perfiles.cargar(args.perfiles).get(args.usuario)
        except _perfiles.PerfilesInvalidos as e:
            print(f"aviso: {e}", file=sys.stderr)
            custodio = None
        if custodio is not None:
            s_u_hex = custodio.s_u.hex()
            perfil = perfil or custodio.perfil
    if s_u_hex is None:
        s_u_hex = getpass.getpass(f"S_u de {args.usuario} (hex, sin eco): ").strip()
    try:
        s_u = bytes.fromhex(s_u_hex)
    except ValueError:
        raise SystemExit("S_u no es hexadecimal valido")
    if len(s_u) != 32:
        raise SystemExit("S_u debe tener 32 bytes (64 caracteres hex)")
    perfil = perfil or PERFIL_INTEGRANTE
    if perfil not in PERFILES_VALIDOS:
        raise SystemExit(f"perfil invalido: {perfil} (validos: {', '.join(sorted(PERFILES_VALIDOS))})")
    return s_u, perfil


def _cli() -> int:
    """Loop interactivo minimo para la demo: conectar, login, y leer
    comandos de stdin hasta "salir"."""
    ap = argparse.ArgumentParser(prog="python3 -m cliente.custodio", description="Cliente de BOVEDA-1")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--puerto", type=int, default=PUERTO_ASILO)
    ap.add_argument("--usuario", help="nombre del custodio")
    ap.add_argument("--perfil", help="perfil con el que operar (por defecto, el de perfiles.txt)")
    ap.add_argument("--s-u", dest="s_u", help="secreto S_u en hex (64 caracteres)")
    ap.add_argument("--perfiles", default=str(_RUTA_PERFILES), help="ruta a perfiles.txt (solo desarrollo local)")
    ap.add_argument("--asilo", action="store_true", help="pedir asilo en vez de iniciar sesion")
    ap.add_argument("--peticion", default="solicito asilo")
    ap.add_argument("--sal", default="un poco de sal")
    ap.add_argument("--harina", default="un poco de harina")
    args = ap.parse_args()

    if args.asilo:
        try:
            _mostrar(pedir_asilo(args.host, args.puerto, args.peticion, args.sal, args.harina))
            return 0
        except ErrorProtocolo as e:
            print(f"error: {e}", file=sys.stderr)
            return 1

    if not args.usuario:
        ap.error("falta --usuario (o use --asilo)")
    s_u, perfil = _credenciales(args)

    with Custodio(args.host, args.puerto, args.usuario, perfil, s_u) as c:
        try:
            c.conectar()
            if not c.login():
                print("Login rechazado.", file=sys.stderr)
                return 1
            print(f"Sesion iniciada como {args.usuario} (perfil: {perfil}). Escriba 'ayuda'.")
            while c.conectado:
                try:
                    linea = input("boveda> ")
                except (EOFError, KeyboardInterrupt):
                    print()
                    break
                partes = linea.split(maxsplit=2)
                if not partes:
                    continue
                cmd = partes[0].lower()
                if cmd in ("salir", "exit", "quit"):
                    break
                if cmd == "ayuda":
                    print(_AYUDA)
                elif cmd == "consultar" and len(partes) == 2:
                    _mostrar(c.consultar(partes[1]))
                elif cmd == "agregar" and len(partes) == 3:
                    _mostrar(c.agregar(partes[1], partes[2]))
                elif cmd == "borrar" and len(partes) == 2:
                    _mostrar(c.borrar(partes[1]))
                elif cmd == "cierre" and len(partes) == 1:
                    if input("Esto derrumba la Boveda para todos. Seguro? (s/N) ").strip().lower() != "s":
                        continue
                    _mostrar(c.cierre())
                    if not c.conectado:
                        print("Sesion cerrada.")
                else:
                    print("Comando no reconocido o argumentos incorrectos. Escriba 'ayuda'.")
        except ErrorProtocolo as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(_cli())