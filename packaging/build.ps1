<#
.SYNOPSIS
  Compila el agente, arma el MSI y —si hay certificado— lo firma.

.DESCRIPTION
  Un solo guion para la maquina del desarrollador y para CI: si las dos rutas
  divergen, el MSI que se prueba no es el que se publica.

  SOBRE LA FIRMA. Sin firmar, este instalador tiene mala vida por delante:
  SmartScreen lo marca como "editor desconocido", y el binario toca el registro
  de directivas de almacenamiento y el archivo hosts, que es justo el perfil de
  comportamiento que la heuristica de cualquier antivirus considera hostil. Un
  certificado OV normal ayuda pero arrastra reputacion desde cero; uno EV da
  confianza inmediata en SmartScreen. Es un gasto que no se puede saltar en un
  producto de seguridad que se instala en equipos ajenos.

  La firma es OPCIONAL en este guion a proposito: sin ella se puede desarrollar
  y probar. Lo que no se puede es publicar; de eso se encarga el CI, que exige
  firma en las etiquetas de version.

.PARAMETER Version
  Version del producto en formato N.N.N. Es la que ve el Panel de control y la
  que decide si un MSI actualiza a otro.

.PARAMETER CertificadoPfx
  Ruta a un .pfx. Alternativa local a la firma en la nube; para publicar de
  verdad, mejor Azure Trusted Signing (ver ClaveAzure).

.PARAMETER ClaveAzure
  Si se indica, se firma con Azure Trusted Signing usando las variables de
  entorno AZURE_TENANT_ID, AZURE_CLIENT_ID y AZURE_CLIENT_SECRET. Es la via
  recomendada: la clave privada nunca baja a disco, ni al del desarrollador ni
  al del runner de CI.
#>
[CmdletBinding()]
param(
  [string]$Version = '0.1.0',
  [string]$CertificadoPfx,
  [string]$ClavePfx,
  [switch]$ClaveAzure,
  [string]$Salida = "$PSScriptRoot\..\dist"
)

$ErrorActionPreference = 'Stop'
$raiz = Resolve-Path "$PSScriptRoot\.."

if ($Version -notmatch '^\d+\.\d+\.\d+$') {
  throw "La version debe ser N.N.N (Windows Installer ignora un cuarto componente al comparar versiones, y dos MSI que solo difieran en el se consideran iguales: la actualizacion no se aplicaria)."
}

function Buscar-Signtool {
  # El SDK de Windows instala un signtool por arquitectura. Hay que coger el que
  # corresponde a la maquina que compila: el de arm64 en un x64 existe pero no
  # ejecuta, y el error que da no menciona la arquitectura.
  $arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'x64' }
  $c = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' -Recurse -Filter signtool.exe -EA SilentlyContinue |
       Where-Object { $_.FullName -like "*\$arch\*" } |
       Sort-Object FullName -Descending | Select-Object -First 1
  if (-not $c) { throw "no se encontro signtool.exe ($arch). Instale el Windows SDK." }
  return $c.FullName
}

function Firmar([string]$ruta) {
  # RFC 3161 con sello de tiempo NO es opcional: sin el, todo lo firmado deja de
  # validar el dia que caduque el certificado, incluidos los MSI ya desplegados.
  $ts = 'http://timestamp.digicert.com'

  if ($ClaveAzure) {
    # Azure Trusted Signing: la clave privada no baja nunca a disco. En CI es la
    # unica opcion sensata — un .pfx en un secreto de repositorio es una clave de
    # firma que puede exfiltrar cualquiera con permiso de escritura en workflows.
    & $script:signtool sign /v /debug /fd SHA256 /tr $ts /td SHA256 `
      /dlib "$env:AZURE_CODE_SIGNING_DLIB" /dmdf "$PSScriptRoot\azure-signing.json" $ruta
  } else {
    $args = @('sign','/v','/fd','SHA256','/tr',$ts,'/td','SHA256','/f',$CertificadoPfx)
    if ($ClavePfx) { $args += @('/p', $ClavePfx) }
    & $script:signtool @args $ruta
  }
  if ($LASTEXITCODE -ne 0) { throw "fallo la firma de $ruta" }
}

New-Item -ItemType Directory -Path $Salida -Force | Out-Null
$exe = "$Salida\nortis-agent.exe"
$msi = "$Salida\NortisAgent-$Version.msi"

# --- 1. Compilar el agente --------------------------------------------------
# CGO_ENABLED=0 deja un binario sin dependencias de tiempo de ejecucion: se
# copia a un equipo limpio y arranca. Con CGO haria falta un runtime de C que en
# un Windows recien instalado no esta.
Write-Host "==> Compilando el agente ($Version)" -ForegroundColor Cyan
$env:CGO_ENABLED = '0'
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
# La version se inyecta en contract.AgentVersion, que es lo que el agente reporta
# a la consola. Asi el numero del Panel de control, el del MSI y el que ve el
# administrador en el panel son siempre el mismo; si divergieran, el aviso de
# "agente desactualizado" apuntaria a equipos equivocados.
$paqueteContrato = 'github.com/fbolivar/nortis-agent/internal/contract'
& go build -trimpath -ldflags "-s -w -X $paqueteContrato.AgentVersion=$Version" -o $exe "$raiz\cmd\nortis-agent"
if ($LASTEXITCODE -ne 0) { throw "fallo la compilacion del agente" }

# --- 2. Firmar el EXE -------------------------------------------------------
# El ejecutable se firma ANTES de empaquetarlo. Si solo se firmara el MSI, el
# binario que queda en disco —el que ejecuta el antivirus cada arranque— seguiria
# sin firma, y es ese el que importa para la heuristica.
$firmar = $CertificadoPfx -or $ClaveAzure
if ($firmar) {
  $script:signtool = Buscar-Signtool
  Write-Host "==> Firmando el ejecutable" -ForegroundColor Cyan
  Firmar $exe
} else {
  Write-Warning "MSI SIN FIRMAR. Vale para desarrollo. En un equipo de cliente, SmartScreen lo bloqueara y el antivirus puede ponerlo en cuarentena."
}

# --- 3. Armar el MSI --------------------------------------------------------
# Desde la raiz del repositorio: `wix extension add` sin -g deja las extensiones
# en .wix\ del directorio actual, y NuGet.config tambien se resuelve desde ahi.
# Invocar el guion desde otra carpeta fallaria con un "extension no encontrada"
# que no dice nada de la causa.
Write-Host "==> Armando el MSI" -ForegroundColor Cyan
Push-Location $raiz
try {
& wix build `
  -arch x64 `
  -ext WixToolset.Util.wixext `
  -ext WixToolset.UI.wixext `
  -d Version=$Version `
  -d AgentExe=$exe `
  -d IconPath="$PSScriptRoot\nortis.ico" `
  -d LicenciaPath="$PSScriptRoot\licencia.rtf" `
  -o $msi `
  "$PSScriptRoot\nortis-agent.wxs"
} finally { Pop-Location }
if ($LASTEXITCODE -ne 0) { throw "fallo la construccion del MSI" }

# --- 4. Firmar el MSI -------------------------------------------------------
if ($firmar) {
  Write-Host "==> Firmando el MSI" -ForegroundColor Cyan
  Firmar $msi
  & $script:signtool verify /pa /v $msi
  if ($LASTEXITCODE -ne 0) { throw "el MSI no verifica: no se publica" }
}

Write-Host ""
Write-Host "MSI: $msi" -ForegroundColor Green
Get-FileHash $msi -Algorithm SHA256 | Format-List Algorithm, Hash
