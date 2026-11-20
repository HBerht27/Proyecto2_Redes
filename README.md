# BOVEDA-1 — Proyecto 2, Casa 1

Implementación del protocolo BOVEDA-1 (cliente-servidor sobre TCP) para el
curso Redes de Comunicación de Datos, UCR.

Integrantes: Axel Saborío Esquivel, José Roberto Murillo Lozano, Matías
Venegas Sancho.

La especificación del protocolo (framing, formato de mensaje, handshake,
autentificación, confidencialidad, integridad, anti-repetición, permisos y
cierre de emergencia) está en el documento «Especificación pública del
protocolo BÓVEDA-1 (Casa 1)». Este repositorio la implementa.

## Estructura

```
common/      Framing, formato de mensaje y criptografía. Lo comparten
             el servidor y el cliente; no debe divergir entre los dos.
servidor/    La Bóveda: login, perfiles, almacenamiento, permisos,
             cierre de emergencia y asilo.
cliente/     El custodio: handshake, login y comandos por CLI.
datos/       perfiles.txt de prueba (usuario:perfil:S_u_en_hex). El
             almacén (almacen.json) se crea al ejecutar la Bóveda.
capturas/    Captura de Wireshark de una sesión legítima completa.
```

## División de trabajo

- **`common/`** — Roberto. Contrato compartido entre servidor y cliente.
- **`servidor/sesiones.py`, `servidor/comandos.py`, `servidor/boveda.py`** — Axel.
  Un hilo por conexión, límites de disponibilidad (timeout, máximo de
  conexiones) y cierre de emergencia coordinado entre hilos.
- **`servidor/perfiles.py`, `servidor/almacen.py`, `cliente/custodio.py`** — Matías.
  Carga de `perfiles.txt`, capa de almacenamiento y cliente completo
  (conectar, handshake, login, comandos por CLI, asilo).

## Requisitos

Solo biblioteca estándar de Python 3. No hay dependencias que instalar.
Todos los comandos se ejecutan desde la raíz del repo.

## Cómo correr

**Servidor** (escucha en el puerto 5301):

```bash
python3 -m servidor.boveda
```

**Cliente** (el secreto S_u y el perfil se toman de `datos/perfiles.txt`
si se ejecuta en la misma máquina):

```bash
python3 -m cliente.custodio --usuario axel
python3 -m cliente.custodio --usuario roberto
```

Comandos dentro del cliente: `consultar <clave>`, `agregar <clave> <valor>`,
`borrar <clave>` (solo jefe), `cierre` (solo jefe), `ayuda` y `salir`.

**Desde otra máquina**, indicando la dirección de la Bóveda (si no hay
`perfiles.txt` local, el cliente pide el S_u sin eco):

```bash
python3 -m cliente.custodio --host <IP> --usuario axel
```

**Solicitar asilo** (perfil `hacinado`, sin acceso a comandos):

```bash
python3 -m cliente.custodio --host <IP> --asilo
```

Otras opciones: `--puerto`, `--perfil`, `--s-u <hex>`, `--perfiles <ruta>`,
`--peticion`, `--sal` y `--harina`.

## Usuarios de prueba

`datos/perfiles.txt` define a `roberto` (jefe) y a `axel` y `matias`
(integrantes). Formato de cada línea: `usuario:perfil:S_u_en_hex`.

## Captura de Wireshark

`capturas/sesion_legitima.pcapng`: sesión completa con handshake, login y
comandos (filtro `tcp.port == 5301`).

## Nota

El cierre de emergencia elimina `datos/almacen.json`. Si la Bóveda se
interrumpe a mitad del cierre y no arranca, basta con borrar ese archivo.