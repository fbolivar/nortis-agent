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
