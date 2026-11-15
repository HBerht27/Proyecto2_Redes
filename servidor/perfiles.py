"""Carga de perfiles.txt: que usuario tiene que perfil y su secreto S_u.

Formato de cada linea del archivo (uno por custodio), separado por ':':

    usuario:perfil:S_u_en_hex

- usuario: identificador del custodio, sin espacios.
- perfil: "integrante" o "jefe" (hacinado no se declara aqui, se asigna
  solo a quien pide asilo).
- S_u_en_hex: 32 bytes aleatorios en hexadecimal (64 caracteres), el
  secreto de larga duracion que comparte el custodio con la Boveda.

Lineas vacias o que empiezan con '#' se ignoran.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from common.tipos import PERFILES_VALIDOS


@dataclass
class Custodio:
    usuario: str
    perfil: str
    s_u: bytes


class PerfilesInvalidos(Exception):
    pass


def cargar(ruta: str | Path) -> dict[str, Custodio]:
    """Lee perfiles.txt y devuelve {usuario: Custodio}.

    TODO (Matías): completar la carga real.
    - Abrir el archivo, saltar lineas vacias/comentarios.
    - Partir cada linea por ':', validar que el perfil este en
      PERFILES_VALIDOS y que el secreto tenga 32 bytes una vez
      decodificado de hex (bytes.fromhex).
    - Si una linea esta mal formada, lanzar PerfilesInvalidos con el
      numero de linea, no dejar que un typo tumbe todo el servidor en
      produccion (eso se maneja afuera, en boveda.py, con try/except).
    - Pensar que pasa con usuarios duplicados (la ultima linea gana, o
      se rechaza el archivo entero: decidir y dejarlo documentado aqui).
    """
    raise NotImplementedError


def generar_archivo_ejemplo(ruta: str | Path, custodios: list[Custodio]) -> None:
    """Util para pruebas locales: escribe un perfiles.txt a partir de una
    lista de Custodio. No es parte del protocolo, es solo una ayuda de
    desarrollo (por ejemplo para armar datos/perfiles.txt).
    """
    raise NotImplementedError