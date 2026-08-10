# Instalador del agente Nortis

## Construir

```powershell
./packaging/build.ps1 -Version 0.1.0
```

Deja `dist/NortisAgent-0.1.0.msi`. Requiere Go, el SDK de .NET y la herramienta
`wix`:

```powershell
dotnet tool install --global wix --version 5.0.2
wix extension add WixToolset.Util.wixext/5.0.2
wix extension add WixToolset.UI.wixext/5.0.2
```

Las extensiones se resuelven contra el `NuGet.config` del repositorio, no contra
la configuracion global de la maquina. Si su equipo tiene la configuracion global
de NuGet vaciada por politica, la construccion funciona igual.

## Desplegar

Interactivo:

```powershell
msiexec /i NortisAgent-0.1.0.msi
```

Silencioso, que es como lo hara un administrador por GPO o Intune:

```powershell
msiexec /i NortisAgent-0.1.0.msi /qn CLAVE=nrt_live_xxxxx CONSOLA=https://app.nortis.co
```

La credencial se crea en la consola, en **Configuracion → API keys**, y empieza
por `nrt_live_`. La propiedad se llama `CLAVE` para que coincida con lo que el
administrador ve en pantalla, y esta marcada como oculta: no aparece en los
registros de instalacion. Un log de MSI acaba en tickets y en correos, y esta
credencial da de alta endpoints en la organizacion.

Si la credencial esta revocada o mal copiada la instalacion **no** falla: el
binario queda puesto y se puede enrolar despues, sin volver a desplegar a todo el
parque por un error de copiado:

```powershell
& "$env:ProgramFiles\Nortis\Agent\nortis-agent.exe" enroll -key nrt_live_xxxxx -url https://app.nortis.co
```

## Desinstalar

```powershell
msiexec /x NortisAgent-0.1.0.msi /qn
```

El MSI llama a `nortis-agent.exe revert` **despues** de parar el servicio y
**antes** de borrar los archivos. El equipo queda como estaba: el USB vuelve a
escritura, el bloque del archivo hosts se retira y la directiva de DNS-over-HTTPS
se restaura al valor que tuviera el cliente.

Ese orden no es un detalle de estilo. Si los archivos se borraran primero,
desaparece el unico programa que sabe deshacer los controles y el equipo se queda
bloqueado sin herramienta para arreglarlo. Ya pasó una vez, por un fallo del
propio agente, y hubo que editar el registro a mano.

Una **actualizacion** no revierte: la condicion
`REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE` distingue una desinstalacion de la
desinstalacion implicita que hace toda actualizacion mayor. Sin esa segunda
parte, cada version nueva desprotegeria el parque durante unos segundos.

---

## Firma de codigo

**Sin firmar, este instalador no se puede entregar a un cliente.** No es una
formalidad:

- SmartScreen lo presenta como "editor desconocido" y esconde el boton de
  ejecutar detras de un "Mas informacion" que la mayoria no pulsa.
- El binario escribe en `HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies`
  y en `%SystemRoot%\System32\drivers\etc\hosts`. Ese es, literalmente, el patron
  de comportamiento que la heuristica de un antivirus puntua como hostil. Sin
  firma no hay nada que lo compense.
- Windows Defender Application Control y AppLocker, habituales en clientes con
  algo de madurez, sencillamente no ejecutan binarios sin firmar.

### Que opcion tomar

| Opcion | Coste anual aprox. | Reputacion inicial | Donde vive la clave |
|---|---|---|---|
| **Azure Trusted Signing** | ~120 USD | Buena desde el primer dia | HSM de Azure |
| Certificado EV en token | 300–600 USD | Inmediata en SmartScreen | Token USB fisico |
| Certificado OV | 200–400 USD | **Desde cero**: semanas de avisos | Archivo o token |

Recomendacion: **Azure Trusted Signing**. Es lo mas barato, la clave privada no
existe fuera del HSM —no hay token USB que perder ni `.pfx` que filtrar— y CI
puede firmar por OIDC sin ningun secreto de larga duracion.

Un certificado OV es la peor de las tres: cuesta mas que Trusted Signing y
arranca sin reputacion, de modo que durante las primeras semanas SmartScreen
sigue avisando. Se paga por algo que todavia no protege.

Requisito comun a todas: **BC FABRIC SAS debe estar constituida y verificable**
(registro mercantil, direccion, telefono comprobable). La validacion tarda entre
tres dias y dos semanas. Conviene empezarla antes de necesitarla.

### Dar de alta Azure Trusted Signing

1. En Azure, crear un recurso *Trusted Signing Account*.
2. Crear un *Identity Validation* para BC FABRIC SAS y superar la verificacion.
3. Crear un *Certificate Profile* de tipo **Public Trust** — no `Test`: el perfil
   de prueba firma y verifica en la maquina que lo creo, pero su cadena no esta
   en la raiz de confianza de Windows, asi que en el equipo del cliente aparece
   como no firmado.
4. Rellenar `packaging/azure-signing.json` con el endpoint, la cuenta y el perfil.
5. Cargar en GitHub los secretos `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` y
   `AZURE_CLIENT_SECRET` (o configurar OIDC, que evita el secreto de cliente).

Comprobar la firma:

```powershell
Get-AuthenticodeSignature dist\NortisAgent-0.1.0.msi | Format-List Status, SignerCertificate
```

`Status` tiene que ser `Valid`. El CI lo exige antes de publicar el artefacto de
una etiqueta.

### Firmar en local con un .pfx

```powershell
./packaging/build.ps1 -Version 0.1.0 -CertificadoPfx C:\ruta\cert.pfx -ClavePfx 'contrasena'
```

Solo para pruebas. El `.gitignore` bloquea `*.pfx`, `*.p12` y `*.snk`: quien
tenga esa clave privada puede firmar cualquier cosa como BC FABRIC SAS.

---

## Lo que el sello de tiempo evita

`build.ps1` firma siempre con sello RFC 3161. Sin el, todo lo firmado deja de
validar el dia que caduca el certificado — incluidos los MSI ya instalados en
equipos de clientes. Con sello, la firma sigue siendo valida despues de la
caducidad porque se puede demostrar que se hizo mientras el certificado estaba
vigente.

## Pendiente

- **Probar instalacion y desinstalacion reales.** Las tablas del MSI estan
  verificadas (orden de secuencia, condiciones, configuracion del servicio), pero
  un ciclo completo en una maquina limpia todavia no se ha ejecutado. Hacerlo en
  una VM, no en un equipo de trabajo.
- **Enviar el MSI al programa de analisis de Microsoft** una vez firmado, para
  adelantar la reputacion de SmartScreen antes del primer despliegue.
- **Pedir excepcion al antivirus del cliente** para `nortis-agent.exe`. Con firma
  suele bastar, pero las suites con heuristica agresiva pueden seguir marcandolo.
