<#
.SYNOPSIS
  Valida el ciclo completo del agente en una maquina limpia. EJECUTAR ELEVADO.

.DESCRIPTION
  Tres fases que se corren en orden, parando entre ellas para mirar la consola:

    .\validar.ps1 -Fase base       ANTES de instalar nada
    .\validar.ps1 -Fase aplicado   con el agente instalado y la politica puesta
    .\validar.ps1 -Fase final      despues de desinstalar

  La fase `base` guarda una huella del estado del equipo. La fase `final` la
  compara y dice si el equipo volvio EXACTAMENTE a como estaba.

  POR QUE UNA HUELLA Y NO UNA REVISION A OJO: el fallo que costo horas en
  desarrollo fue que la reversion informaba de exito habiendo dejado el USB en
  solo lectura. Comprobar a ojo es justo lo que dejo pasar aquello. La
  comparacion tiene que ser mecanica y tiene que fallar sola.

.PARAMETER Fase
  base | aplicado | final
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateSet('base','aplicado','final')][string]$Fase,
  [string]$Estado = 'C:\nortis-validacion'
)

$ErrorActionPreference = 'Continue'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
      [Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Hay que ejecutarlo como administrador: lee claves de HKLM y el archivo hosts."
}

New-Item -ItemType Directory -Path $Estado -Force | Out-Null
$hosts = "$env:SystemRoot\System32\drivers\etc\hosts"

# Huella del equipo. Solo lo que el agente puede tocar: si se comparara todo,
# cualquier actualizacion de Windows haria fallar la validacion y en dos dias
# nadie la miraria.
function Huella {
  $sd    = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies' -EA SilentlyContinue
  $usb   = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' -EA SilentlyContinue
  $edge  = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -EA SilentlyContinue
  $chrome= Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Google\Chrome' -EA SilentlyContinue

  [ordered]@{
    UsbstorStart  = if ($usb)    { [string]$usb.Start }             else { '(ausente)' }
    WriteProtect  = if ($sd -and $null -ne $sd.WriteProtect) { [string]$sd.WriteProtect } else { '(ausente)' }
    EdgeDoH       = if ($edge   -and $edge.DnsOverHttpsMode)   { $edge.DnsOverHttpsMode }   else { '(ausente)' }
    ChromeDoH     = if ($chrome -and $chrome.DnsOverHttpsMode) { $chrome.DnsOverHttpsMode } else { '(ausente)' }
    # El contenido del hosts se compara por hash: interesa que vuelva IDENTICO,
    # no parecido. Una linea de mas es una linea que alguien tendra que borrar.
    HostsHash     = (Get-FileHash $hosts -Algorithm SHA256).Hash
    HostsBytes    = (Get-Item $hosts).Length
    HostsNortis   = [bool](Select-String -Path $hosts -Pattern 'BEGIN NORTIS' -Quiet)
  }
}

function Mostrar($h) { $h.GetEnumerator() | ForEach-Object { "  {0,-14} {1}" -f $_.Key, $_.Value } }

$actual = Huella

switch ($Fase) {

  'base' {
    "=== FASE 1: ESTADO INICIAL (antes de instalar) ==="
    Mostrar $actual
    $actual | ConvertTo-Json | Out-File "$Estado\base.json" -Encoding utf8

    ""
    "Servicio NortisAgent presente = " + [bool](Get-Service NortisAgent -EA SilentlyContinue)
    "Carpeta de datos presente     = " + (Test-Path "$env:ProgramData\Nortis")
    ""
    "Huella guardada. Ya se puede instalar el MSI."
  }

  'aplicado' {
    "=== FASE 2: CON EL AGENTE APLICANDO POLITICA ==="
    Mostrar $actual

    ""
    "--- Servicio ---"
    $s = Get-Service NortisAgent -EA SilentlyContinue
    if ($s) { "  estado = " + $s.Status + " / arranque = " + (Get-CimInstance Win32_Service -Filter "Name='NortisAgent'").StartMode }
    else    { "  NO ESTA INSTALADO" }

    ""
    "--- Enrolamiento ---"
    $cred = "$env:ProgramData\Nortis\Agent\endpoint.cred"
    "  credencial de endpoint = " + $(if (Test-Path $cred) { "presente ($((Get-Item $cred).Length) bytes)" } else { "AUSENTE: el enrolamiento fallo" })

    ""
    "--- Lineas que el agente puso en hosts ---"
    Select-String -Path $hosts -Pattern 'NORTIS|0\.0\.0\.0' -EA SilentlyContinue |
      ForEach-Object { "  " + $_.Line }

    ""
    "--- Ultimas lineas del log del agente ---"
    Get-Content "$env:ProgramData\Nortis\Agent\agent.log" -Tail 15 -EA SilentlyContinue |
      ForEach-Object { "  " + $_ }

    ""
    "Comprobar AHORA en la consola que el endpoint aparece y reporta latido."
    "Despues, desinstalar y correr: .\validar.ps1 -Fase final"
  }

  'final' {
    "=== FASE 3: DESPUES DE DESINSTALAR ==="
    if (-not (Test-Path "$Estado\base.json")) { throw "Falta base.json: la fase 'base' no se ejecuto." }
    $base = Get-Content "$Estado\base.json" -Raw | ConvertFrom-Json

    $fallos = @()
    foreach ($k in $actual.Keys) {
      $antes = [string]$base.$k
      $ahora = [string]$actual[$k]
      $ok = $antes -eq $ahora
      "{0} {1,-14} antes={2}  ahora={3}" -f $(if ($ok) { 'OK  ' } else { 'FALLA' }), $k, $antes, $ahora
      if (-not $ok) { $fallos += $k }
    }

    ""
    "--- Restos en el equipo ---"
    $restos = @()
    if (Get-Service NortisAgent -EA SilentlyContinue)          { $restos += 'el servicio NortisAgent sigue registrado' }
    if (Test-Path "$env:ProgramFiles\Nortis")                  { $restos += "queda $env:ProgramFiles\Nortis" }
    if (Test-Path "$env:ProgramData\Nortis\Agent\enforce-state.json") { $restos += 'queda enforce-state.json: la reversion no lo borro' }
    if ($restos) { $restos | ForEach-Object { "  - $_" } } else { "  ninguno" }

    ""
    if ($fallos.Count -eq 0 -and $restos.Count -eq 0) {
      Write-Host "VALIDACION SUPERADA: el equipo quedo como estaba." -ForegroundColor Green
      exit 0
    }
    Write-Host "VALIDACION FALLIDA. Sin arreglar esto, el agente NO se entrega." -ForegroundColor Red
    if ($fallos) { "  no se restauraron: " + ($fallos -join ', ') }
    exit 1
  }
}
