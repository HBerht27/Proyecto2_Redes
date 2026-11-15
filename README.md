# BOVEDA-1 — Proyecto 2, Casa 1

Implementacion del protocolo BOVEDA-1 (cliente-servidor sobre TCP) para el
curso Redes de Comunicacion de Datos, UCR.

Integrantes: Axel Saborío Esquivel, José Roberto Murillo Lozano, Matías
Venegas Sancho.

La especificación completa del protocolo (framing, formato de mensaje,
handshake, autentificación, confidencialidad/integridad/anti-repetición,
permisos y cierre de emergencia) está en el documento de diseño ya
aprobado; este repositorio la implementa tal cual quedó ahí.

## Estructura

```
common/      Framing, formato de mensaje y criptografía. Lo comparten
             el servidor y el cliente; no debe divergir entre los dos.
servidor/    La Boveda: login, perfiles, almacenamiento, permisos,
             cierre de emergencia y asilo.
cliente/     El custodio: handshake, login y comandos por CLI.
datos/       perfiles.txt de prueba para desarrollo local.
capturas/    Capturas de Wireshark para la entrega de la Fase 1.
```

## División de trabajo

- **`common/`** — Roberto. Contrato compartido; queda cerrado desde el
  inicio para que servidor y cliente se puedan desarrollar en paralelo
  sin bloquearse entre sí.
- **`servidor/sesiones.py`, `servidor/comandos.py`, `servidor/boveda.py`** — Axel.
  Es la parte con concurrencia: un hilo por conexión, límites de
  disponibilidad (timeout, máximo de conexiones) y el cierre de
  emergencia coordinado entre hilos.
- **`servidor/perfiles.py`, `servidor/almacen.py`, `cliente/custodio.py`** — Matías.
  Carga de `perfiles.txt`, la capa de almacenamiento (sin hilos
  involucrados) y el cliente completo, que es lineal: conectar,
  handshake, login, comandos por CLI.

Se repartió así en vez de servidor/cliente tal cual porque la parte de
concurrencia y coordinación del servidor (`sesiones.py`/`comandos.py`/
`boveda.py`) es bastante más pesada que el cliente por sí solo; moviendo
`perfiles.py` y `almacen.py` (autocontenidos, sin sockets) a Matías
queda más parejo.

Todos los archivos de estos dos grupos traen comentarios en cada
función indicando qué debe hacer y con qué parte de la especificación
corresponde; faltan los cuerpos.

## Cómo correr

Solo biblioteca estándar de Python 3, no hay dependencias que instalar.

```bash
python3 -m servidor.boveda          # levanta la Boveda en el puerto 5301
python3 -m cliente.custodio         # cliente interactivo
```

(Ambos comandos ejecutados desde la raíz del repo.)

## Pendiente antes de la demo (martes 18)

- Completar `servidor/` y `cliente/`.
- `datos/perfiles.txt` real para el entorno de laboratorio.
- Captura de Wireshark de una sesión legítima completa (handshake +
  login + un comando) en `capturas/`.
- Ensayar la demo de 3–5 min: login, agregar, consultar, borrar (jefe),
  cierre de emergencia.