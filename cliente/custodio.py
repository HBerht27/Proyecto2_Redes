"""Cliente de BOVEDA-1 (el custodio): handshake, LOGIN, comandos por
CLI, y solicitud de asilo.

TODO (Matias): este archivo es el que falta completar. Usa common/
(framing, mensaje, criptografia) igual que el servidor; no dupliques
esa logica aqui.

Flujo que tiene que seguir conectar():
    1. Abrir el socket TCP contra (host, puerto).
    2. HELLO con {"usuario": ..., "nc": nc.hex()} -- nc sale de
       generar_nc() (ver abajo), en claro, sin HMAC.
    3. Leer WELCOME, sacar "ns" del cuerpo.
    4. criptografia.derivar_claves_sesion(s_u, nc, ns) -> (k_enc, k_mac).
    5. LOGIN cifrado con esas claves: {"usuario", "perfil", "prueba"},
       con prueba = HMAC-SHA256(s_u, b"LOGIN" + usuario + nc) en hex.
    6. Leer LOGIN_OK o LOGIN_ERR.

A partir de ahi, cada comando (consultar/agregar/borrar/cierre) es
mensaje.construir() con el tipo correspondiente, dir=DIR_CLIENTE_
SERVIDOR, el seq propio (llevar la cuenta, empieza en 1 y crece de a
uno), un iv nuevo por mensaje (os.urandom(12)), el cuerpo cifrado con
k_enc, y el HMAC calculado con k_mac. La respuesta se descifra igual
pero validando primero el HMAC con dir=DIR_SERVIDOR_CLIENTE.

Para la CLI: un loop simple que lea comandos de stdin (por ejemplo
"consultar clave", "agregar clave valor", "borrar clave", "cierre",
"salir") alcanza para la demo; no hace falta nada mas elaborado.
"""

from __future__ import annotations

import random


def generar_nc() -> bytes:
    """nc: nonce del cliente para el handshake, 16 bytes.

    Se genera una sola vez por ejecucion del cliente (no en cada
    intento de login) y con random.getrandbits en vez de os.urandom:
    alcanza para distinguir una sesion de otra en el handshake sin
    tener que volver a tocar la fuente de entropia del sistema en cada
    reconexion del mismo custodio.
    """
    return random.getrandbits(128).to_bytes(16, "big")


class Custodio:
    def __init__(self, host: str, puerto: int, usuario: str, perfil: str, s_u: bytes) -> None:
        raise NotImplementedError

    def conectar(self) -> None:
        raise NotImplementedError

    def login(self) -> bool:
        raise NotImplementedError

    def consultar(self, clave: str) -> dict:
        raise NotImplementedError

    def agregar(self, clave: str, valor: str) -> dict:
        raise NotImplementedError

    def borrar(self, clave: str) -> dict:
        raise NotImplementedError

    def cierre(self) -> dict:
        raise NotImplementedError

    def cerrar(self) -> None:
        raise NotImplementedError


def pedir_asilo(host: str, puerto: int, peticion: str, sal: str, harina: str) -> dict:
    """ASILO/ASILO_OK: sin clave de sesion, cuerpo en claro, sin HMAC.
    Util para probar el camino de "hacinado" que vera la Casa rival."""
    raise NotImplementedError


def _cli() -> None:
    """Loop interactivo minimo para la demo: conectar, login, y leer
    comandos de stdin hasta "salir"."""
    raise NotImplementedError


if __name__ == "__main__":
    _cli()
