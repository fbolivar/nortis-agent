# Nortis Agent

Agente de endpoint para Windows de [Nortis](https://github.com/fbolivar/nortis):
recolecta telemetría, aplica las políticas definidas en la consola y reporta
incidentes.

Servicio de Windows en Go, binario único sin dependencias de runtime.

## Estado

**Fase 0 completa y verificada contra la API real. Fase 1 en curso:** ya hay dos
recolectores, sesión y aplicaciones.

| | |
|---|---|
| Ciclo de vida del servicio | ✅ arranque, ciclos periódicos y parada limpia |
| Cola local SQLite | ✅ con tope, confirmación diferida y reintentos acotados |
| Credencial | ✅ cifrada con DPAPI, verificada en disco |
| Enrolamiento | ✅ contra `/api/agent/enroll` real |
| Sincronización | ✅ lote enviado y confirmado por la consola |
| Política | ✅ descargada, cacheada y aplicada desde caché sin red |
| Latido | ✅ con detección de cuarentena y de política nueva |
| Recolector de sesión | ✅ logon, logoff e inactividad vía WTS |
| Recolector de aplicaciones | ✅ `app_open` con categoría y ruta del ejecutable |
| Recolector de navegación | ⛔ resto de Fase 1 |
| Recolectores de Fase 2+ | ⛔ no empezar hasta revisión |
| Instalador MSI firmado | ⛔ pendiente |

## Uso

```powershell
# 1. Registrar el equipo (credencial generada en la consola)
nortis-agent enroll -key nrt_live_... -url https://su-consola

# 2. Instalar como servicio (requiere PowerShell como administrador)
nortis-agent install
nortis-agent start

# Diagnóstico
nortis-agent status      # estado local, sin tocar la red
nortis-agent selftest    # valida el camino cola -> consola
nortis-agent run         # ejecuta en primer plano
```

Todo el estado vive en `C:\ProgramData\Nortis\Agent`: configuración, credencial
cifrada, cola y log. Desinstalar es borrar esa carpeta.

## Decisiones de diseño

**El recolector nunca espera a la red.** Todo evento se escribe primero en
SQLite; el sincronizador drena la cola aparte. Si el equipo pasa días sin
conexión no se pierde telemetría, y si la consola está caída el usuario no nota
absolutamente nada.

**`Dequeue` no borra.** El borrado ocurre solo cuando la consola confirma. Si
borrara al leer y la petición fallara después, esos eventos se perderían para
siempre — justo lo que la cola existe para evitar.

**La cola tiene tope y descarta lo más antiguo.** Sin tope, un equipo semanas sin
red llenaría el disco: el mismo fallo que el producto previene, causado por el
propio agente. Y en forense lo reciente es lo que se mira primero.

**Un evento imposible no bloquea la cola.** Tras agotar reintentos se descarta.
Si no, un solo evento que la consola siempre rechaza dejaría al equipo mudo para
siempre.

**Sin red se aplica la última política conocida.** Se persiste en la cola, así
que un equipo que reinicia sin conexión no queda desprotegido.

**Si la consola habla una versión de contrato mayor, no se aplica la política
nueva.** Aplicar media política de seguridad es peor que no aplicarla: el panel
diría que el equipo está cubierto cuando no lo está.

**La credencial se guarda después de que la consola la acepte**, nunca antes. Y
cifrada con DPAPI atada a la máquina: si el disco se clona, deja de funcionar.

**`InsecureSkipVerify` no aparece en el código, ni para desarrollo.** Un agente
que acepta cualquier certificado es un agente interceptable, y por ahí se va la
telemetría de toda la organización.

**Reinstalar el agente no saca un equipo de cuarentena** ni lo duplica en el
inventario: la identidad es la huella de máquina derivada del `MachineGuid`.

## Protección anti-manipulación

El modelo es **resistencia con autorización**, no "imposible de eliminar". Nada
legítimo es irreversible: un agente que ni el administrador ni el propio IT
pueden quitar es un rootkit, lo pone en cuarentena el antivirus, y si falla deja
el equipo inservible. Lo que se impone es más fuerte de lo que parece y sigue
siendo recuperable.

- **El usuario sin privilegios no puede tocarlo.** Un DACL restrictivo en el
  objeto de servicio le niega detener, pausar, reconfigurar y borrar; otro en el
  directorio de datos le niega borrar la cola de eventos o la credencial. Lo
  impone Windows, no un vigilante en espacio de usuario que se pueda matar.
- **El administrador tampoco puede, por sí solo.** En el estado endurecido, ni
  los administradores conservan permiso de parada o borrado: solo SYSTEM. Quitar
  el agente exige un **vale de desinstalación** firmado por la consola, ligado a
  ese `endpoint_id` y con caducidad. Un vale robado de un equipo no vale en otro.
- **Interbloqueo de seguridad.** El agente se NIEGA a endurecer si no hay una
  clave pública de consola configurada (`console_pubkey.pem`). Sin vía de
  desbloqueo no se endurece: así nunca se construye por accidente el equipo sin
  salida. Es `internal/tamper/tamper.go` → `ErrSinClaveConsola`.
- **El servicio (SYSTEM) es quien afloja**, tras revalidar el vale, porque es el
  único con permiso para reescribir el DACL. El administrador deja el vale con
  `nortis-agent unlock -token …`; poder dejar el archivo no da autoridad, la
  firma de la consola sí.

```powershell
nortis-agent tamper-status              # ¿está endurecido? ¿hay clave de consola?
nortis-agent lock                        # forzar el endurecimiento
nortis-agent unlock -token <vale>        # autorizar la desinstalación
nortis-agent uninstall                   # dentro de la ventana de 10 min
```

La clave de la autoridad de desbloqueo se genera con la herramienta de
operaciones, que **no se despliega** en los equipos y guarda la clave privada
fuera del agente:

```powershell
go run ./tools/uninstall-token keygen -out .
# -> console_pubkey.pem  (va al agente)   console_privkey.pem (SECRETO, custodia)
go run ./tools/uninstall-token sign -endpoint <endpoint_id> -priv console_privkey.pem
```

> **Pendiente (consola).** La emisión de vales vivirá en la consola: un endpoint
> que, con la sesión de un admin, firme un vale para un `endpoint_id` con la
> clave privada bajo custodia. El formato del vale ya es el que valida el agente;
> falta el lado servidor y la UI. Hasta entonces se emiten con la herramienta de
> operaciones.

## Contratos

Los tipos de `internal/contract` son el espejo en Go de lo que la consola declara
en TypeScript. Cualquier cambio en un lado exige el cambio en el otro; cuando
divergen, el síntoma no es un error de compilación sino telemetría descartada en
silencio — por eso el sincronizador registra siempre cuántos eventos se
rechazaron.

## Desarrollo

```powershell
go test ./...              # cola y ciclo de vida
go vet ./...
go build ./cmd/nortis-agent
```

Los tests del servicio apuntan a un puerto que nadie escucha, a propósito:
validan que el ciclo de vida funciona **aunque la consola esté caída**, que es el
escenario que de verdad importa.
