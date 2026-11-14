"""Framing por prefijo de longitud sobre un socket TCP.

Un socket TCP no respeta limites de mensaje: un solo recv() puede
devolver medio mensaje, varios mensajes juntos, o cualquier otra
fraccion del flujo de bytes. Por eso cada mensaje va precedido por 4
bytes (entero sin signo, big-endian) con su longitud, y el receptor
siempre lee exactamente esa cantidad antes de entregar el mensaje a la
capa de protocolo.
"""

import socket
import struct

from common.tipos import TAMANO_MAXIMO_MENSAJE

PREFIJO = struct.Struct(">I")  # 4 bytes, big-endian, sin signo


class ConexionCerrada(Exception):
    """El otro lado cerro el socket antes de completar un mensaje."""


class MensajeDemasiadoGrande(Exception):
    """El prefijo de longitud excede TAMANO_MAXIMO_MENSAJE."""


def _recibir_exacto(sock: socket.socket, n: int) -> bytes:
    partes = []
    restante = n
    while restante > 0:
        trozo = sock.recv(restante)
        if not trozo:
            raise ConexionCerrada(f"se esperaban {restante} bytes mas y el socket se cerro")
        partes.append(trozo)
        restante -= len(trozo)
    return b"".join(partes)


def enviar(sock: socket.socket, mensaje: bytes) -> None:
    sock.sendall(PREFIJO.pack(len(mensaje)) + mensaje)


def recibir(sock: socket.socket) -> bytes:
    (longitud,) = PREFIJO.unpack(_recibir_exacto(sock, 4))
    if longitud > TAMANO_MAXIMO_MENSAJE:
        raise MensajeDemasiadoGrande(f"anunciados {longitud} bytes, maximo {TAMANO_MAXIMO_MENSAJE}")
    return _recibir_exacto(sock, longitud)
