"""Almacenamiento de la informacion sensible de cada custodio.

Un custodio solo puede leer, agregar o borrar dentro de su propio
espacio de claves (el de la sesion autenticada), nunca el de otro. Y la
`clave` que manda el cliente en CONSULTAR/AGREGAR/BORRAR NUNCA debe
usarse para construir una ruta de archivo real (nada de
`open(f"datos/{clave}.txt")`): eso seria un path traversal explotable
por cualquier custodio autenticado, y cuenta como vulnerabilidad no
planificada aparte de los dos defectos asignados.

TODO (Axel): elegir una de estas dos formas de persistencia y
completar las funciones de abajo:

1. Diccionario en memoria: {usuario: {clave: valor}}, con un volcado
   periodico (o al CIERRE) a un unico archivo JSON/pickle en disco.
   Mas simple, suficiente para la demo.
2. SQLite (modulo sqlite3, viene en la biblioteca estandar): una tabla
   (usuario, clave, valor) con PRIMARY KEY (usuario, clave).

Cualquiera que sea la opcion, estas funciones son las que usa
comandos.py; el resto del servidor no debe tocar el almacenamiento
directo.
"""

from __future__ import annotations


class Almacen:
    def __init__(self) -> None:
        raise NotImplementedError

    def consultar(self, usuario: str, clave: str) -> str | None:
        """Devuelve el valor guardado por `usuario` bajo `clave`, o None
        si no existe. Nunca debe poder devolver datos de otro usuario."""
        raise NotImplementedError

    def agregar(self, usuario: str, clave: str, valor: str) -> None:
        """Guarda (o sobrescribe) `clave` -> `valor` dentro del espacio de
        `usuario` unicamente."""
        raise NotImplementedError

    def borrar(self, usuario: str, clave: str) -> bool:
        """Borra `clave` del espacio de `usuario`. Devuelve si existia."""
        raise NotImplementedError

    def derrumbar(self) -> None:
        """Para el cierre de emergencia: sobrescribir y eliminar todo el
        almacen (no solo vaciar el diccionario en memoria si tambien hay
        algo en disco)."""
        raise NotImplementedError
