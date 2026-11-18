"""Almacenamiento de la informacion sensible de cada custodio.

Un custodio solo puede leer, agregar o borrar dentro de su propio
espacio de claves (el de la sesion autenticada), nunca el de otro. Y la
`clave` que manda el cliente en CONSULTAR/AGREGAR/BORRAR NUNCA se usa
para construir una ruta de archivo real: aqui la clave es solo una llave
de diccionario, asi que no hay path traversal posible.

Persistencia (opcion 1 del TODO): diccionario en memoria
{usuario: {clave: valor}} que se vuelca completo a UN solo archivo JSON
(datos/almacen.json) despues de cada agregar/borrar. La escritura es
atomica (archivo temporal + os.replace), asi que un corte a media
escritura no deja el archivo a medias.

Concurrencia: boveda.py usa un hilo por conexion y todos comparten una
misma instancia de Almacen. Todas las operaciones toman el mismo Lock.

Limites (disponibilidad): clave, valor y cantidad de claves por usuario
estan acotados para que un custodio autenticado no pueda llenar la
memoria ni el disco del servidor.

Errores: cualquier problema (entrada invalida, limite excedido, almacen
derrumbado, fallo de disco) lanza AlmacenError. comandos.py lo convierte
en un ERROR generico para el cliente.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
RUTA_POR_DEFECTO = RAIZ / "datos" / "almacen.json"

MAX_USUARIO_BYTES = 64
MAX_CLAVE_BYTES = 64
MAX_VALOR_BYTES = 4096
MAX_CLAVES_POR_USUARIO = 100

_AUSENTE = object()


class AlmacenError(Exception):
    pass


def _validar_texto(nombre: str, x: object, maximo: int, vacio_ok: bool = False) -> str:
    if not isinstance(x, str):
        raise AlmacenError(f"{nombre} debe ser texto")
    if not x and not vacio_ok:
        raise AlmacenError(f"{nombre} no puede ser vacio")
    try:
        tam = len(x.encode("utf-8"))
    except UnicodeEncodeError:
        raise AlmacenError(f"{nombre} no es texto UTF-8 valido") from None
    if tam > maximo:
        raise AlmacenError(f"{nombre} excede {maximo} bytes")
    return x


class Almacen:
    def __init__(self, ruta: str | Path | None = None) -> None:
        self._ruta = Path(ruta) if ruta else RUTA_POR_DEFECTO
        self._lock = threading.Lock()
        self._datos: dict[str, dict[str, str]] = {}
        self._derrumbado = False
        self._cargar()

    # ---------- persistencia (siempre con el lock tomado, salvo __init__) ----------

    def _cargar(self) -> None:
        if not self._ruta.exists():
            return
        try:
            crudo = json.loads(self._ruta.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise AlmacenError(f"no se pudo leer {self._ruta}: {e}") from e
        if not isinstance(crudo, dict):
            raise AlmacenError(f"{self._ruta}: formato invalido")
        for usuario, claves in crudo.items():
            if not isinstance(claves, dict) or not all(
                isinstance(k, str) and isinstance(v, str) for k, v in claves.items()
            ):
                raise AlmacenError(f"{self._ruta}: formato invalido")
        self._datos = crudo

    def _guardar(self) -> None:
        """Escribe todo el diccionario al JSON de forma atomica."""
        tmp = None
        try:
            self._ruta.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(
                dir=self._ruta.parent, prefix=".almacen-", suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self._datos, f)
                f.flush()
                os.fsync(f.fileno())
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            os.replace(tmp, self._ruta)
        except OSError as e:
            if tmp is not None:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
            raise AlmacenError(f"no se pudo guardar: {e}") from e

    def _verificar_vivo(self) -> None:
        if self._derrumbado:
            raise AlmacenError("almacen derrumbado")

    # ---------- API que usa comandos.py ----------

    def consultar(self, usuario: str, clave: str) -> str | None:
        """Devuelve el valor guardado por `usuario` bajo `clave`, o None
        si no existe. Nunca devuelve datos de otro usuario."""
        _validar_texto("usuario", usuario, MAX_USUARIO_BYTES)
        _validar_texto("clave", clave, MAX_CLAVE_BYTES)
        with self._lock:
            self._verificar_vivo()
            return self._datos.get(usuario, {}).get(clave)

    def agregar(self, usuario: str, clave: str, valor: str) -> None:
        """Guarda (o sobrescribe) `clave` -> `valor` dentro del espacio de
        `usuario` unicamente."""
        _validar_texto("usuario", usuario, MAX_USUARIO_BYTES)
        _validar_texto("clave", clave, MAX_CLAVE_BYTES)
        _validar_texto("valor", valor, MAX_VALOR_BYTES, vacio_ok=True)
        with self._lock:
            self._verificar_vivo()
            espacio = self._datos.get(usuario)
            if (
                espacio is not None
                and clave not in espacio
                and len(espacio) >= MAX_CLAVES_POR_USUARIO
            ):
                raise AlmacenError("limite de claves por usuario alcanzado")

            creo_espacio = espacio is None
            if creo_espacio:
                espacio = self._datos[usuario] = {}
            anterior = espacio.get(clave, _AUSENTE)
            espacio[clave] = valor
            try:
                self._guardar()
            except AlmacenError:
                if anterior is _AUSENTE:
                    del espacio[clave]
                else:
                    espacio[clave] = anterior  # type: ignore[assignment]
                if creo_espacio and not espacio:
                    del self._datos[usuario]
                raise

    def borrar(self, usuario: str, clave: str) -> bool:
        """Borra `clave` del espacio de `usuario`. Devuelve si existia."""
        _validar_texto("usuario", usuario, MAX_USUARIO_BYTES)
        _validar_texto("clave", clave, MAX_CLAVE_BYTES)
        with self._lock:
            self._verificar_vivo()
            espacio = self._datos.get(usuario)
            if espacio is None or clave not in espacio:
                return False
            valor = espacio.pop(clave)
            vacio = not espacio
            if vacio:
                del self._datos[usuario]
            try:
                self._guardar()
            except AlmacenError:
                if vacio:
                    self._datos[usuario] = espacio
                espacio[clave] = valor
                raise
            return True

    def derrumbar(self) -> None:
        """Para el cierre de emergencia: sobrescribir y eliminar todo el
        almacen (memoria y disco). Es irreversible durante esta ejecucion:
        despues de esto toda operacion lanza AlmacenError. Es idempotente."""
        with self._lock:
            self._derrumbado = True
            self._datos = {}
            candidatos = [self._ruta]
            candidatos += self._ruta.parent.glob(".almacen-*.tmp") \
                if self._ruta.parent.exists() else []
            for ruta in candidatos:
                self._destruir_archivo(ruta)

    @staticmethod
    def _destruir_archivo(ruta: Path) -> None:
        try:
            tam = ruta.stat().st_size
        except OSError:
            return  # no existe: nada que destruir
        try:
            with open(ruta, "r+b") as f:
                f.write(os.urandom(tam))
                f.flush()
                os.fsync(f.fileno())
        except OSError:
            pass  # aun asi intentamos borrarlo
        try:
            ruta.unlink()
        except OSError:
            pass