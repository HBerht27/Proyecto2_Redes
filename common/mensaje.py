"""Empaquetado y desempaquetado del formato de mensaje de BOVEDA-1.

Cabecera (25 bytes, todo big-endian):
    ver(1) | tipo(1) | dir(1) | seq(8) | iv(12) | plen(2)

Seguida del cuerpo (plen bytes) y, salvo para HELLO/WELCOME/ASILO/
ASILO_OK, de un HMAC-SHA256 (32 bytes) sobre cabecera + cuerpo ya
cifrado. Tamano total: 57 + plen bytes (25 + plen + 32), o 25 + plen
para los cuatro tipos sin HMAC.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from common import criptografia
from common.tipos import VERSION, TIPOS_SIN_HMAC

_CABECERA = struct.Struct(">BBBQ12sH")


@dataclass
class Mensaje:
    tipo: int
    dir: int
    seq: int
    iv: bytes
    cuerpo: bytes
    hmac: bytes | None  # None solo para HELLO/WELCOME/ASILO/ASILO_OK


class MensajeInvalido(Exception):
    pass


def construir(tipo: int, dir_: int, seq: int, iv: bytes, cuerpo: bytes, k_mac: bytes | None = None) -> bytes:
    cabecera = _CABECERA.pack(VERSION, tipo, dir_, seq, iv, len(cuerpo))
    if tipo in TIPOS_SIN_HMAC:
        return cabecera + cuerpo
    if k_mac is None:
        raise MensajeInvalido(f"el tipo 0x{tipo:02x} requiere k_mac para calcular el HMAC")
    valor_hmac = criptografia.calcular_hmac(k_mac, cabecera + cuerpo)
    return cabecera + cuerpo + valor_hmac


def parsear(datos: bytes) -> Mensaje:
    if len(datos) < _CABECERA.size:
        raise MensajeInvalido("mensaje mas corto que la cabecera minima")

    ver, tipo, dir_, seq, iv, plen = _CABECERA.unpack_from(datos, 0)
    if ver != VERSION:
        raise MensajeInvalido(f"version de protocolo desconocida: 0x{ver:02x}")

    resto = datos[_CABECERA.size:]
    sin_hmac = tipo in TIPOS_SIN_HMAC
    esperado = plen if sin_hmac else plen + criptografia.TAMANO_HMAC
    if len(resto) != esperado:
        raise MensajeInvalido(f"tamano inconsistente: plen={plen}, recibidos {len(resto)} bytes de cuerpo+hmac")

    cuerpo = resto[:plen]
    valor_hmac = None if sin_hmac else resto[plen:]
    return Mensaje(tipo=tipo, dir=dir_, seq=seq, iv=iv, cuerpo=cuerpo, hmac=valor_hmac)


def verificar(msg: Mensaje, datos_originales: bytes, k_mac: bytes) -> bool:
    """Revalida el HMAC de un mensaje ya parseado contra los bytes crudos recibidos."""
    if msg.hmac is None:
        raise MensajeInvalido("este tipo de mensaje no lleva HMAC")
    cabecera_y_cuerpo = datos_originales[: len(datos_originales) - criptografia.TAMANO_HMAC]
    return criptografia.verificar_hmac(k_mac, cabecera_y_cuerpo, msg.hmac)
