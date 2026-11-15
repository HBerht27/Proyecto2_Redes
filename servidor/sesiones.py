"""Estado por conexion: claves de sesion, contadores de secuencia y
el procesamiento del LOGIN.

Cada hilo de boveda.py crea una Sesion al terminar el handshake y la
usa durante toda la vida de la conexion. Nada de esto se comparte entre
conexiones (ver "Aislamiento por conexion" en la especificacion).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from common import criptografia
from common.tipos import PERFIL_HACINADO

from servidor.perfiles import Custodio


@dataclass
class Sesion:
    k_enc: bytes
    k_mac: bytes
    nc: bytes  # nonce del cliente de este handshake, lo necesita verificar_prueba

    usuario: str | None = None
    perfil: str = PERFIL_HACINADO

    seq_cliente_visto: int = 0  # ultimo seq aceptado en mensajes cliente->servidor
    seq_servidor: int = 0  # contador propio para las respuestas servidor->cliente

    def siguiente_seq_servidor(self) -> int:
        self.seq_servidor += 1
        return self.seq_servidor

    def seq_cliente_valido(self, seq: int) -> bool:
        """TODO (Axel): un mensaje del cliente solo es valido si su seq es
        estrictamente mayor que el ultimo aceptado (anti-repeticion).
        Esta funcion se llama DESPUES de que el HMAC ya valido (ver nota
        en la especificacion: nunca actualizar seq con un mensaje sin
        autenticar). Si es valido, actualizar seq_cliente_visto aqui
        mismo antes de devolver True."""
        raise NotImplementedError


def verificar_prueba(custodio: Custodio, usuario: str, nc: bytes, prueba: bytes) -> bool:
    """prueba = HMAC-SHA256(S_u, 'LOGIN' || usuario || nc), calculada por
    el cliente. TODO (Axel): recalcularla con el S_u guardado para este
    custodio y compararla en tiempo constante (hmac.compare_digest, o
    criptografia.verificar_hmac si el formato calza)."""
    raise NotImplementedError


def procesar_login(custodio: Custodio | None, sesion: Sesion, cuerpo_login: dict) -> bool:
    """Valida el LOGIN y, si la identidad es correcta, deja la sesion
    autenticada. Devuelve True si el login fue exitoso (se puede
    responder LOGIN_OK), False si hay que responder LOGIN_ERR.

    TODO (Axel):
    - Si `custodio` es None (usuario no existe en perfiles.txt),
      devolver False sin mas.
    - Llamar a verificar_prueba(); si no coincide, devolver False.
    - Si coincide, dejar sesion.usuario = custodio.usuario.

    El campo "perfil" del LOGIN indica con que perfil desea operar el
    custodio en esta sesion (ver "Autentificacion del custodio" en la
    especificacion); perfiles.txt sigue siendo la fuente para validar
    que el usuario existe y para la prueba de identidad de arriba.
    """
    if custodio is None:
        return False
    if not verificar_prueba(custodio, custodio.usuario, sesion.nc, bytes.fromhex(cuerpo_login["prueba"])):
        return False

    sesion.usuario = custodio.usuario
    sesion.perfil = cuerpo_login["perfil"]
    return True
