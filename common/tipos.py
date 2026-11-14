"""Constantes del protocolo BOVEDA-1.

Valores tomados directamente de la especificación pública
(Diseño del protocolo - Boveda de la Casa 1, v1.0).
"""

VERSION = 0x01

# Tipos de mensaje
HELLO = 0x01
WELCOME = 0x02
LOGIN = 0x10
LOGIN_OK = 0x11
LOGIN_ERR = 0x1F
CONSULTAR = 0x20
AGREGAR = 0x21
BORRAR = 0x22
CIERRE = 0x23
RESP = 0x30
ERROR = 0x3F
ASILO = 0x40
ASILO_OK = 0x41

NOMBRES = {
    HELLO: "HELLO",
    WELCOME: "WELCOME",
    LOGIN: "LOGIN",
    LOGIN_OK: "LOGIN_OK",
    LOGIN_ERR: "LOGIN_ERR",
    CONSULTAR: "CONSULTAR",
    AGREGAR: "AGREGAR",
    BORRAR: "BORRAR",
    CIERRE: "CIERRE",
    RESP: "RESP",
    ERROR: "ERROR",
    ASILO: "ASILO",
    ASILO_OK: "ASILO_OK",
}

# HELLO, WELCOME, ASILO y ASILO_OK viajan antes de que exista clave de
# sesion (o sin clave de sesion en absoluto, en el caso del asilo), asi
# que no llevan HMAC y su cuerpo va en claro.
TIPOS_SIN_HMAC = {HELLO, WELCOME, ASILO, ASILO_OK}

# Direccion del mensaje (campo "dir")
DIR_CLIENTE_SERVIDOR = 0x00
DIR_SERVIDOR_CLIENTE = 0x01

# Perfiles de permiso
PERFIL_HACINADO = "hacinado"
PERFIL_INTEGRANTE = "integrante"
PERFIL_JEFE = "jefe"
PERFILES_VALIDOS = {PERFIL_INTEGRANTE, PERFIL_JEFE}  # hacinado no se declara por login

PUERTO_ASILO = 5301
TAMANO_MAXIMO_MENSAJE = 64 * 1024  # 64 KiB, incluye el prefijo de longitud
