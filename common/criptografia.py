"""Primitivas criptograficas de BOVEDA-1, todas sobre hmac/hashlib.

No se usa ninguna libreria externa de cifrado: la confidencialidad sale
de un flujo de clave construido con HMAC-SHA256 en modo contador, y la
integridad de HMAC-SHA256 directo. HKDF-SHA256 tampoco existe en la
biblioteca estandar de Python, asi que se implementa aqui siguiendo el
RFC 5869 (HKDF-Extract + HKDF-Expand).
"""

import hashlib
import hmac

TAMANO_HASH = hashlib.sha256().digest_size  # 32
TAMANO_BLOQUE_KEYSTREAM = 32
TAMANO_HMAC = 32


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, longitud: int) -> bytes:
    bloques = []
    anterior = b""
    contador = 1
    while len(b"".join(bloques)) < longitud:
        anterior = hmac.new(prk, anterior + info + bytes([contador]), hashlib.sha256).digest()
        bloques.append(anterior)
        contador += 1
    return b"".join(bloques)[:longitud]


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, longitud: int) -> bytes:
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, longitud)


def derivar_claves_sesion(s_u: bytes, nc: bytes, ns: bytes) -> tuple[bytes, bytes]:
    """K = HKDF-SHA256(ikm=S_u, salt=nc||ns, info="BOVEDA1/v1", L=64).

    Devuelve (k_enc, k_mac), cada uno de 32 bytes.
    """
    k = hkdf_sha256(ikm=s_u, salt=nc + ns, info=b"BOVEDA1/v1", longitud=64)
    return k[:32], k[32:64]


def _keystream(clave: bytes, iv: bytes, nbytes: int) -> bytes:
    bloques = []
    contador = 0
    while len(bloques) * TAMANO_BLOQUE_KEYSTREAM < nbytes:
        bloque = hmac.new(clave, iv + contador.to_bytes(4, "big"), hashlib.sha256).digest()
        bloques.append(bloque)
        contador += 1
    return b"".join(bloques)[:nbytes]


def cifrar(claro: bytes, k_enc: bytes, iv: bytes) -> bytes:
    flujo = _keystream(k_enc, iv, len(claro))
    return bytes(a ^ b for a, b in zip(claro, flujo))


# El flujo de clave es simetrico: cifrar y descifrar son la misma operacion.
descifrar = cifrar


def calcular_hmac(k_mac: bytes, datos: bytes) -> bytes:
    return hmac.new(k_mac, datos, hashlib.sha256).digest()


def verificar_hmac(k_mac: bytes, datos: bytes, hmac_recibido: bytes) -> bool:
    esperado = calcular_hmac(k_mac, datos)
    return hmac.compare_digest(esperado, hmac_recibido)
