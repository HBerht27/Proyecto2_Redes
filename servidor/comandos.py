"""Manejo de los comandos autenticados: CONSULTAR, AGREGAR, BORRAR,
CIERRE, y construccion de RESP/ERROR.

Tabla de permisos (ver "Perfiles de permiso" en la especificacion):

    Capacidad              hacinado  integrante  jefe
    Consultar informacion     No        Si         Si
    Agregar informacion       No        Si         Si
    Borrar informacion        No        No         Si
    Cierre de emergencia      No        No         Si

TODO (Axel): implementar manejar_comando() usando almacen.Almacen y la
Sesion activa. Cada handler recibe el cuerpo JSON ya descifrado (dict)
y la Sesion, y devuelve el dict de respuesta (que boveda.py se encarga
de cifrar y enviar como RESP, o como ERROR si algo fallo).

Puntos a no dejar pasar (vulnerabilidades no planificadas, fuera de los
dos defectos asignados):
- CONSULTAR/AGREGAR/BORRAR siempre operan sobre almacen bajo
  sesion.usuario, nunca sobre un usuario que venga en el cuerpo del
  mensaje (si el cliente llegara a mandarlo, ignorarlo).
- BORRAR y CIERRE verifican sesion.perfil == PERFIL_JEFE antes de
  hacer nada.
- Cualquier excepcion al parsear el cuerpo (JSON invalido, falta
  "clave", etc.) debe resultar en ERROR generico, no en que boveda.py
  se caiga.
"""

from __future__ import annotations

from servidor.almacen import Almacen
from servidor.sesiones import Sesion


class PermisoDenegado(Exception):
    pass


def manejar_consultar(almacen: Almacen, sesion: Sesion, cuerpo: dict) -> dict:
    raise NotImplementedError


def manejar_agregar(almacen: Almacen, sesion: Sesion, cuerpo: dict) -> dict:
    raise NotImplementedError


def manejar_borrar(almacen: Almacen, sesion: Sesion, cuerpo: dict) -> dict:
    raise NotImplementedError


def manejar_cierre(almacen: Almacen, sesion: Sesion, cuerpo: dict) -> dict:
    """Ademas de responder {"ok": true}, quien llama a esto (boveda.py)
    es responsable de: derrumbar el almacen, cerrar el socket a la
    escucha y rechazar toda conexion nueva durante esta ejecucion del
    servicio. Esta funcion solo valida el permiso y arma la respuesta;
    no le corresponde tocar sockets."""
    raise NotImplementedError


DESPACHO = {
    # tipo de mensaje -> handler. Completar con las constantes de
    # common.tipos (CONSULTAR, AGREGAR, BORRAR, CIERRE) una vez que los
    # handlers de arriba esten listos.
}
