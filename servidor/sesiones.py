"""Estado de la sesion y autenticacion del custodio."""

from __future__ import annotations

import hmac
from dataclasses import dataclass

from common import criptografia
from common.tipos import PERFIL_HACINADO, PERFILES_VALIDOS

from servidor.perfiles import Custodio


@dataclass
class Sesion:
    k_enc: bytes
    k_mac: bytes
    nc: bytes

    usuario: str | None = None
    perfil: str = PERFIL_HACINADO

    seq_cliente_visto: int = 0
    seq_servidor: int = 0

    def siguiente_seq_servidor(self) -> int:
        self.seq_servidor += 1
        return self.seq_servidor

    def seq_cliente_valido(self, seq: int) -> bool:
        if not isinstance(seq, int):
            return False

        if seq <= self.seq_cliente_visto:
            return False

        self.seq_cliente_visto = seq
        return True


def verificar_prueba(
    custodio: Custodio,
    usuario: str,
    nc: bytes,
    prueba: bytes
) -> bool:

    datos = b"LOGIN" + usuario.encode("utf-8") + nc

    prueba_esperada = criptografia.calcular_hmac(
        custodio.s_u,
        datos
    )

    return hmac.compare_digest(prueba_esperada, prueba)


def procesar_login(
    custodio: Custodio | None,
    sesion: Sesion,
    cuerpo_login: dict
) -> bool:

    if custodio is None:
        return False

    if not isinstance(cuerpo_login, dict):
        return False

    usuario = cuerpo_login.get("usuario")
    perfil = cuerpo_login.get("perfil")
    prueba_hex = cuerpo_login.get("prueba")

    if usuario != custodio.usuario:
        return False

    if perfil not in PERFILES_VALIDOS:
        return False

    if not isinstance(prueba_hex, str):
        return False

    try:
        prueba = bytes.fromhex(prueba_hex)
    except ValueError:
        return False

    if not verificar_prueba(
        custodio,
        usuario,
        sesion.nc,
        prueba
    ):
        return False

    sesion.usuario = custodio.usuario
    sesion.perfil = perfil

    return True