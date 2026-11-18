"""Carga de perfiles.txt: que usuario tiene que perfil y su secreto S_u.
 
Formato de cada linea del archivo (uno por custodio), separado por ':':
 
    usuario:perfil:S_u_en_hex
 
- usuario: identificador del custodio, sin espacios.
- perfil: "integrante" o "jefe" (hacinado no se declara aqui, se asigna
  solo a quien pide asilo).
- S_u_en_hex: 32 bytes aleatorios en hexadecimal (64 caracteres), el
  secreto de larga duracion que comparte el custodio con la Boveda.
 
Lineas vacias o que empiezan con '#' se ignoran.
 
Decision sobre usuarios duplicados: se RECHAZA el archivo entero
(PerfilesInvalidos). Si dos lineas definen al mismo usuario es casi seguro
un error de edicion, y "la ultima gana" podria dar un perfil o un secreto
que nadie quiso.
"""
 
from __future__ import annotations
 
import re
import secrets
from dataclasses import dataclass
from pathlib import Path
 
from common.tipos import PERFILES_VALIDOS
 
# Solo estos caracteres en un nombre de usuario (sirve tambien para que
# almacen.py pueda usarlo sin riesgo en rutas).
_USUARIO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
 
_PERFIL_ASILO = "hacinado"  # no se declara en el archivo
_TAM_S_U = 32
 
 
@dataclass
class Custodio:
    usuario: str
    perfil: str
    s_u: bytes
 
 
class PerfilesInvalidos(Exception):
    pass
 
 
def cargar(ruta: str | Path) -> dict[str, Custodio]:
    """Lee perfiles.txt y devuelve {usuario: Custodio}.
 
    Lanza PerfilesInvalidos (con el numero de linea) si el archivo no
    existe o alguna linea esta mal formada. No devuelve resultados
    parciales: o carga todo o falla.
    """
    ruta = Path(ruta)
    try:
        texto = ruta.read_text(encoding="utf-8")
    except OSError as e:
        raise PerfilesInvalidos(f"no se pudo leer {ruta}: {e}") from e
 
    custodios: dict[str, Custodio] = {}
    for n, linea in enumerate(texto.splitlines(), start=1):
        linea = linea.strip()
        if not linea or linea.startswith("#"):
            continue
 
        campos = [c.strip() for c in linea.split(":")]
        if len(campos) != 3:
            raise PerfilesInvalidos(
                f"{ruta}:{n}: se esperaba 'usuario:perfil:S_u_en_hex'")
        usuario, perfil, s_u_hex = campos
        perfil = perfil.lower()
 
        if not _USUARIO_RE.match(usuario):
            raise PerfilesInvalidos(f"{ruta}:{n}: usuario invalido")
        if perfil not in PERFILES_VALIDOS or perfil == _PERFIL_ASILO:
            raise PerfilesInvalidos(
                f"{ruta}:{n}: perfil '{perfil}' no se puede declarar aqui")
        try:
            s_u = bytes.fromhex(s_u_hex)
        except ValueError:
            raise PerfilesInvalidos(
                f"{ruta}:{n}: S_u no es hexadecimal valido") from None
        if len(s_u) != _TAM_S_U:
            raise PerfilesInvalidos(
                f"{ruta}:{n}: S_u debe tener {_TAM_S_U} bytes "
                f"({_TAM_S_U * 2} caracteres hex)")
        if usuario in custodios:
            raise PerfilesInvalidos(f"{ruta}:{n}: usuario repetido '{usuario}'")
 
        custodios[usuario] = Custodio(usuario, perfil, s_u)
 
    return custodios
 
 
def generar_archivo_ejemplo(ruta: str | Path, custodios: list[Custodio]) -> None:
    """Util para pruebas locales: escribe un perfiles.txt a partir de una
    lista de Custodio. No es parte del protocolo, es solo una ayuda de
    desarrollo (por ejemplo para armar datos/perfiles.txt).
    """
    lineas = ["# usuario:perfil:S_u_en_hex"]
    for c in custodios:
        lineas.append(f"{c.usuario}:{c.perfil}:{c.s_u.hex()}")
    ruta = Path(ruta)
    ruta.parent.mkdir(parents=True, exist_ok=True)
    ruta.write_text("\n".join(lineas) + "\n", encoding="utf-8")
 
 
if __name__ == "__main__":
    # python3 -m servidor.perfiles  -> arma datos/perfiles.txt con secretos nuevos
    raiz = Path(__file__).resolve().parent.parent
    destino = raiz / "datos" / "perfiles.txt"
    if destino.exists():
        raise SystemExit(f"{destino} ya existe; no lo sobrescribo")
    generar_archivo_ejemplo(destino, [
        Custodio("jefe1", "jefe", secrets.token_bytes(_TAM_S_U)),
        Custodio("axel", "integrante", secrets.token_bytes(_TAM_S_U)),
        Custodio("matias", "integrante", secrets.token_bytes(_TAM_S_U)),
        Custodio("roberto", "integrante", secrets.token_bytes(_TAM_S_U)),
    ])
    print(f"escrito {destino}")