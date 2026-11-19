"""Manejo de comandos y permisos de la Boveda."""

from __future__ import annotations

from common.tipos import (
    CONSULTAR,
    AGREGAR,
    BORRAR,
    CIERRE,
    RESP,
    ERROR,
    PERFIL_INTEGRANTE,
    PERFIL_JEFE,
)

from servidor.almacen import Almacen, AlmacenError
from servidor.sesiones import Sesion


class PermisoDenegado(Exception):
    pass


class ComandoInvalido(Exception):
    pass


def verificar_permiso(sesion: Sesion, solo_jefe: bool = False) -> None:
    if sesion.usuario is None:
        raise PermisoDenegado

    if solo_jefe:
        if sesion.perfil != PERFIL_JEFE:
            raise PermisoDenegado
    elif sesion.perfil not in (PERFIL_INTEGRANTE, PERFIL_JEFE):
        raise PermisoDenegado


def manejar_consultar(almacen: Almacen, sesion: Sesion, cuerpo: dict) -> dict:
    verificar_permiso(sesion)

    clave = cuerpo.get("clave")

    if not isinstance(clave, str):
        raise ComandoInvalido

    valor = almacen.consultar(sesion.usuario, clave)

    return {
        "clave": clave,
        "valor": valor
    }


def manejar_agregar(almacen: Almacen, sesion: Sesion, cuerpo: dict) -> dict:
    verificar_permiso(sesion)

    clave = cuerpo.get("clave")
    valor = cuerpo.get("valor")

    if not isinstance(clave, str) or not isinstance(valor, str):
        raise ComandoInvalido

    almacen.agregar(sesion.usuario, clave, valor)

    return {"ok": True}


def manejar_borrar(almacen: Almacen, sesion: Sesion, cuerpo: dict) -> dict:
    verificar_permiso(sesion, solo_jefe=True)

    clave = cuerpo.get("clave")

    if not isinstance(clave, str):
        raise ComandoInvalido

    almacen.borrar(sesion.usuario, clave)

    return {"ok": True}


def manejar_cierre(almacen: Almacen, sesion: Sesion, cuerpo: dict) -> dict:
    verificar_permiso(sesion, solo_jefe=True)

    if cuerpo:
        raise ComandoInvalido

    return {"ok": True}


DESPACHO = {
    CONSULTAR: manejar_consultar,
    AGREGAR: manejar_agregar,
    BORRAR: manejar_borrar,
    CIERRE: manejar_cierre,
}


def manejar_comando(
    tipo: int,
    almacen: Almacen,
    sesion: Sesion,
    cuerpo: dict
) -> tuple[int, dict]:

    try:
        if not isinstance(cuerpo, dict):
            raise ComandoInvalido

        if tipo not in DESPACHO:
            raise ComandoInvalido

        respuesta = DESPACHO[tipo](almacen, sesion, cuerpo)

        return RESP, respuesta

    except (PermisoDenegado, ComandoInvalido, AlmacenError):
        return ERROR, {"mensaje": "error"}