//go:build windows

// Package inventory recolecta el inventario de software y hardware del equipo.
//
// TODO EN MODO USUARIO. El software sale de las claves de desinstalacion del
// registro (lo mismo que muestra "Programas y caracteristicas"); el hardware, de
// HARDWARE\DESCRIPTION y de dos llamadas a kernel32. No se instala nada ni se
// consulta WMI —mas lento y con mas superficie—: registro y un par de syscalls
// bastan y son baratos, que importa para un barrido cada varias horas.
package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/fbolivar/nortis-agent/internal/contract"
)

// Recolectar devuelve el hardware (mapa suelto) y la lista de software instalado.
func Recolectar(ctx context.Context) (map[string]any, []contract.SoftwareItem) {
	hw := recolectarHardware()
	estadoCifrado(ctx, hw)
	hw["network"] = recolectarRed(ctx)
	if sec := posturaSeguridad(ctx); sec != nil {
		hw["security"] = sec
	}
	if acc := recolectarCuentas(ctx); acc != nil {
		hw["accounts"] = acc
	}
	if upd := recolectarActualizaciones(ctx); upd != nil {
		hw["updates"] = upd
	}
	if v := consultarPS(ctx, scriptPuertos, 20*time.Second); v != nil {
		hw["listening_ports"] = v
	}
	if v := consultarPS(ctx, scriptShares, 20*time.Second); v != nil {
		hw["shares"] = v
	}
	if v := consultarPS(ctx, scriptAutoruns, 20*time.Second); v != nil {
		hw["autoruns"] = v
	}
	if v := consultarPS(ctx, scriptUSB, 20*time.Second); v != nil {
		hw["usb_history"] = v
	}
	if v := consultarPS(ctx, scriptConfianza, 30*time.Second); v != nil {
		hw["trust"] = v
	}
	if v := consultarPS(ctx, scriptRuntime, 25*time.Second); v != nil {
		hw["runtime"] = v
	}
	if v := consultarPS(ctx, scriptFIM, 20*time.Second); v != nil {
		hw["fim"] = v
	}
	if v := consultarPS(ctx, scriptLan, 20*time.Second); v != nil {
		hw["lan_hosts"] = v
	}
	return hw, recolectarSoftware()
}

var procGetTickCount64 = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount64")

// uptimeSegundos devuelve cuantos segundos lleva encendido el equipo (util para
// "lleva mucho sin reiniciar"). GetTickCount64 no envuelve a las ~49 dias.
func uptimeSegundos() uint64 {
	r, _, _ := procGetTickCount64.Call()
	return uint64(r) / 1000
}

// scriptPostura consulta el estado de seguridad del equipo en una sola llamada:
// antivirus (Defender), cortafuegos por perfil y si hay un reinicio pendiente.
// Cada bloque es tolerante a fallo (equipos sin Defender/NetSecurity) y sale como
// JSON para que el servidor lo interprete.
const scriptPostura = `$av=try{Get-MpComputerStatus -ErrorAction Stop|Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureAge,QuickScanEndTime,FullScanEndTime}catch{$null};` +
	`$fw=try{Get-NetFirewallProfile -ErrorAction Stop|Select-Object Name,Enabled}catch{$null};` +
	`$th=try{Get-MpThreat -ErrorAction Stop|Sort-Object SeverityID -Descending|Select-Object -First 15 ThreatName,SeverityID,IsActive}catch{$null};` +
	`$rb=(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending');` +
	`[pscustomobject]@{antivirus=$av;firewall=$fw;threats=$th;pending_reboot=[bool]$rb}|ConvertTo-Json -Compress -Depth 4`

// posturaSeguridad devuelve el estado de seguridad como mapa suelto, o nil si no
// se pudo consultar. Corre como SYSTEM (estado de maquina, no de sesion).
func posturaSeguridad(ctx context.Context) map[string]any {
	ctx2, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx2, "powershell.exe",
		"-NoProfile", "-NonInteractive", "-Command", scriptPostura).Output()
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(bytes.TrimSpace(out), &m) != nil {
		return nil
	}
	return m
}

// scriptCuentas audita cuentas y accesos en una sola llamada: usuarios locales
// (nombre, habilitado, ultimo inicio), los miembros del grupo Administradores
// —resuelto por SID S-1-5-32-544 para que funcione en cualquier idioma de
// Windows— y cuantos inicios de sesion FALLIDOS (evento 4625) hubo en 24 h. Todo
// tolerante a fallo: un bloque que no se puede leer sale nulo, no rompe el resto.
const scriptCuentas = `$u=try{Get-LocalUser -ErrorAction Stop|Select-Object Name,Enabled,@{n='LastLogon';e={if($_.LastLogon){$_.LastLogon.ToString('o')}else{$null}}}}catch{$null};` +
	`$adm=try{$g=Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop;@(Get-LocalGroupMember -Group $g.Name -ErrorAction Stop|Select-Object -ExpandProperty Name)}catch{$null};` +
	`$fail=try{@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=(Get-Date).AddDays(-1)} -ErrorAction Stop).Count}catch{0};` +
	`[pscustomobject]@{users=$u;admins=$adm;failed_logons_24h=$fail}|ConvertTo-Json -Compress -Depth 4`

// recolectarCuentas devuelve la auditoria de cuentas como mapa suelto, o nil si
// no se pudo consultar. Corre como SYSTEM (puede leer el registro de Seguridad).
func recolectarCuentas(ctx context.Context) map[string]any {
	ctx2, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx2, "powershell.exe",
		"-NoProfile", "-NonInteractive", "-Command", scriptCuentas).Output()
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(bytes.TrimSpace(out), &m) != nil {
		return nil
	}
	return m
}

// scriptActualizaciones consulta el estado de parches del equipo: cuantas
// actualizaciones estan pendientes (COM Microsoft.Update.Session, la via estandar
// sin modulos), sus titulos, la fecha del ultimo parche (Get-HotFix) y si el
// Windows Update automatico esta configurado (registro AUOptions: 4 = automatico).
// La busqueda de pendientes consulta a Windows Update y puede tardar, por eso el
// colector corre con un timeout amplio y sale nulo si no responde.
const scriptActualizaciones = `$p=try{$s=New-Object -ComObject Microsoft.Update.Session;$r=$s.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'");[pscustomobject]@{count=$r.Updates.Count;titles=@($r.Updates|Select-Object -First 15 -ExpandProperty Title)}}catch{$null};` +
	`$hf=try{(Get-HotFix -ErrorAction Stop|Where-Object{$_.InstalledOn}|Sort-Object InstalledOn -Descending|Select-Object -First 1).InstalledOn.ToString('o')}catch{$null};` +
	`$au=try{(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -ErrorAction Stop).AUOptions}catch{$null};` +
	`[pscustomobject]@{pending=$p;last_hotfix=$hf;au_options=$au}|ConvertTo-Json -Compress -Depth 4`

// recolectarActualizaciones devuelve el estado de parches como mapa suelto, o nil
// si no se pudo consultar. Corre como SYSTEM. Timeout amplio: la busqueda de
// actualizaciones pendientes contacta a Windows Update.
func recolectarActualizaciones(ctx context.Context) map[string]any {
	ctx2, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx2, "powershell.exe",
		"-NoProfile", "-NonInteractive", "-Command", scriptActualizaciones).Output()
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(bytes.TrimSpace(out), &m) != nil {
		return nil
	}
	return m
}

// consultarPS corre un script de PowerShell que devuelve JSON y lo deserializa a
// un valor generico (objeto o arreglo, segun lo que emita ConvertTo-Json).
// Devuelve nil ante cualquier fallo o salida vacia. Se usa para los colectores de
// auditoria cuya forma la decide el propio script.
func consultarPS(ctx context.Context, script string, timeout time.Duration) any {
	ctx2, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	out, err := exec.CommandContext(ctx2, "powershell.exe",
		"-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		return nil
	}
	t := bytes.TrimSpace(out)
	if len(t) == 0 {
		return nil
	}
	var v any
	if json.Unmarshal(t, &v) != nil {
		return nil
	}
	return v
}

// Puertos TCP a la escucha, con el proceso dueño: exposicion de red del equipo.
// Se acota a 60 puertos unicos para no inflar el inventario.
const scriptPuertos = `@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue|Sort-Object LocalPort -Unique|Select-Object -First 60|ForEach-Object{[pscustomobject]@{port=$_.LocalPort;address=$_.LocalAddress;process=(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}})|ConvertTo-Json -Compress -Depth 3`

// Recursos compartidos SMB que NO son administrativos (los que terminan en $:
// C$, ADMIN$, IPC$). Un recurso compartido inesperado es un vector de fuga.
const scriptShares = `@(Get-SmbShare -ErrorAction SilentlyContinue|Where-Object{$_.Name -notlike '*$'}|Select-Object Name,Path)|ConvertTo-Json -Compress -Depth 3`

// Entradas de autoarranque en las claves Run del registro de maquina: deteccion
// de persistencia (malware que se re-lanza en cada arranque).
const scriptAutoruns = `$keys=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run');` +
	`$o=foreach($k in $keys){if(Test-Path $k){$p=Get-ItemProperty $k;$p.PSObject.Properties|Where-Object{$_.Name -notmatch '^PS' -and $_.Name -ne '(default)'}|ForEach-Object{[pscustomobject]@{name=$_.Name;command=[string]$_.Value;location=$k}}}};` +
	`@($o)|ConvertTo-Json -Compress -Depth 3`

// Historial de dispositivos USB de almacenamiento conectados alguna vez, leido de
// USBSTOR. Las claves persisten para dispositivos ya desconectados: trazabilidad
// para DLP (que memoria/disco se conecto a este equipo).
const scriptUSB = `@(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' -ErrorAction SilentlyContinue|ForEach-Object{Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue}|ForEach-Object{$p=Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue;[pscustomobject]@{name=$p.FriendlyName;id=$_.PSChildName}}|Where-Object{$_.name}|Select-Object -First 60)|ConvertTo-Json -Compress -Depth 3`

// Confianza del equipo: TPM (presente/listo), Secure Boot (activo) y certificados
// de la maquina proximos a caducar (60 dias). Cada bloque tolera fallo: equipos
// sin TPM o con BIOS antiguo salen nulos.
const scriptConfianza = `$tpm=try{$t=Get-Tpm -ErrorAction Stop;[pscustomobject]@{present=$t.TpmPresent;ready=$t.TpmReady}}catch{$null};` +
	`$sb=try{[bool](Confirm-SecureBootUEFI -ErrorAction Stop)}catch{$null};` +
	`$certs=try{@(Get-ChildItem Cert:\LocalMachine\My -ErrorAction Stop|Where-Object{$_.NotAfter -lt (Get-Date).AddDays(60)}|Select-Object -First 20 @{n='subject';e={$_.Subject}},@{n='not_after';e={$_.NotAfter.ToString('o')}})}catch{$null};` +
	`[pscustomobject]@{tpm=$tpm;secure_boot=$sb;expiring_certs=$certs}|ConvertTo-Json -Compress -Depth 4`

// Estado en vivo: usuarios con sesion iniciada ahora (incluye RDP) y los procesos
// que mas memoria consumen. Get-Process -IncludeUserName exige privilegios; el
// agente corre como SYSTEM.
const scriptRuntime = `$top=@(Get-Process -ErrorAction SilentlyContinue|Sort-Object WS -Descending|Select-Object -First 10 @{n='name';e={$_.ProcessName}},@{n='ram_mb';e={[int]($_.WS/1MB)}});` +
	`$users=try{@(Get-Process -IncludeUserName -ErrorAction Stop|Where-Object{$_.UserName -and $_.UserName -notmatch 'NT AUTHORITY|NT-AUTORIDAD|Font Driver|Window Manager|DWM-|UMFD-'}|Select-Object -ExpandProperty UserName -Unique)}catch{$null};` +
	`[pscustomobject]@{top_processes=$top;active_users=$users}|ConvertTo-Json -Compress -Depth 3`

// Integridad de archivos (FIM): hash SHA256 de un conjunto de archivos criticos
// que casi nunca cambian legitimamente. El servidor compara con el inventario
// anterior; un cambio de hash es señal de manipulacion o malware.
const scriptFIM = `@(@("$env:SystemRoot\System32\drivers\etc\hosts","$env:SystemRoot\System32\cmd.exe","$env:SystemRoot\explorer.exe")|ForEach-Object{if(Test-Path $_){[pscustomobject]@{path=$_;hash=(Get-FileHash -Algorithm SHA256 -Path $_ -ErrorAction SilentlyContinue).Hash}}})|Where-Object{$_.hash}|ConvertTo-Json -Compress -Depth 3`

// Descubrimiento de red: vecinos de la subred local (IP + MAC) de la tabla de
// vecinos. El servidor los cruza con los equipos con agente para revelar
// dispositivos NO gestionados (shadow IT) en la red.
const scriptLan = `@(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object{$_.State -in 'Reachable','Stale' -and $_.LinkLayerAddress -match '^[0-9A-Fa-f]{2}-'}|Select-Object -First 100 @{n='ip';e={$_.IPAddress}},@{n='mac';e={$_.LinkLayerAddress.ToLower().Replace('-',':')}})|ConvertTo-Json -Compress -Depth 3`

// recolectarRed devuelve las interfaces de red activas (IP y MAC) y, si el equipo
// esta en WiFi, el nombre de la red. Solo datos de red del propio equipo; nunca
// trafico ni contenido. La IP publica NO se resuelve aqui: la anota el servidor a
// partir del origen de la peticion, que es quien la ve de verdad.
func recolectarRed(ctx context.Context) map[string]any {
	red := map[string]any{}

	ifaces, err := net.Interfaces()
	if err == nil {
		lista := make([]map[string]any, 0, len(ifaces))
		for _, ifc := range ifaces {
			if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
				continue
			}
			var ip string
			addrs, _ := ifc.Addrs()
			for _, a := range addrs {
				if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() {
					ip = ipnet.IP.String()
					break
				}
			}
			if ip == "" {
				continue
			}
			lista = append(lista, map[string]any{
				"name": ifc.Name,
				"ip":   ip,
				"mac":  ifc.HardwareAddr.String(),
			})
		}
		red["interfaces"] = lista
	}

	if ssid := wifiSSID(ctx); ssid != "" {
		red["wifi_ssid"] = ssid
	}
	return red
}

// wifiSSID devuelve el nombre de la red WiFi conectada, o "" si no hay o no se
// pudo leer. Se apoya en `netsh wlan show interfaces`; el nombre del campo SSID
// no se traduce, asi que el parseo es estable entre idiomas.
func wifiSSID(ctx context.Context) string {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx2, "netsh", "wlan", "show", "interfaces").Output()
	if err != nil {
		return ""
	}
	for _, linea := range strings.Split(string(out), "\n") {
		t := strings.TrimSpace(linea)
		// "SSID  : MiRed" pero NO "BSSID : ..".
		if strings.HasPrefix(t, "SSID") && !strings.HasPrefix(t, "BSSID") {
			if i := strings.Index(t, ":"); i >= 0 {
				return strings.TrimSpace(t[i+1:])
			}
		}
	}
	return ""
}

// clavesDesinstalacion son las tres vistas del registro donde Windows anota los
// programas instalados: 64 bits, 32 bits (WOW6432Node) y por-maquina. NOTA: el
// agente corre como SYSTEM, asi que los programas instalados SOLO para el usuario
// interactivo (HKCU de esa persona) no se ven aqui; se cubre lo instalado a nivel
// de maquina, que es la inmensa mayoria del software corporativo.
var clavesDesinstalacion = []struct {
	raiz registry.Key
	ruta string
}{
	{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
	{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
}

func recolectarSoftware() []contract.SoftwareItem {
	vistos := map[string]bool{}
	var out []contract.SoftwareItem

	for _, c := range clavesDesinstalacion {
		raiz, err := registry.OpenKey(c.raiz, c.ruta, registry.READ)
		if err != nil {
			continue
		}
		nombres, _ := raiz.ReadSubKeyNames(-1)
		raiz.Close()

		for _, n := range nombres {
			sub, err := registry.OpenKey(c.raiz, c.ruta+`\`+n, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			nombre, _, _ := sub.GetStringValue("DisplayName")
			version, _, _ := sub.GetStringValue("DisplayVersion")
			publicador, _, _ := sub.GetStringValue("Publisher")
			sysComp, _, _ := sub.GetIntegerValue("SystemComponent")
			padre, _, _ := sub.GetStringValue("ParentKeyName")
			tipo, _, _ := sub.GetStringValue("ReleaseType")
			sub.Close()

			// Se descarta lo que no es un programa "de verdad": componentes del
			// sistema, entradas hijas (parches de un producto) y actualizaciones.
			// Sin este filtro el inventario se llena de miles de KB de Windows.
			if nombre == "" || sysComp == 1 || padre != "" {
				continue
			}
			switch tipo {
			case "Security Update", "Update Rollup", "Hotfix":
				continue
			}

			clave := strings.ToLower(strings.TrimSpace(nombre) + "|" + strings.TrimSpace(version))
			if vistos[clave] {
				continue
			}
			vistos[clave] = true
			out = append(out, contract.SoftwareItem{
				Name:      strings.TrimSpace(nombre),
				Version:   strings.TrimSpace(version),
				Publisher: strings.TrimSpace(publicador),
			})
		}
	}
	return out
}

func recolectarHardware() map[string]any {
	hw := map[string]any{
		"cpu_cores":      runtime.NumCPU(),
		"uptime_seconds": uptimeSegundos(),
	}

	if k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`HARDWARE\DESCRIPTION\System\CentralProcessor\0`, registry.QUERY_VALUE); err == nil {
		if v, _, err := k.GetStringValue("ProcessorNameString"); err == nil {
			hw["cpu"] = strings.TrimSpace(v)
		}
		k.Close()
	}

	if k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`HARDWARE\DESCRIPTION\System\BIOS`, registry.QUERY_VALUE); err == nil {
		if v, _, err := k.GetStringValue("SystemManufacturer"); err == nil {
			hw["manufacturer"] = strings.TrimSpace(v)
		}
		if v, _, err := k.GetStringValue("SystemProductName"); err == nil {
			hw["model"] = strings.TrimSpace(v)
		}
		k.Close()
	}

	if total := ramTotalBytes(); total > 0 {
		hw["ram_bytes"] = total
	}
	if total, libre, ok := discoSistema(); ok {
		hw["disk_total_bytes"] = total
		hw["disk_free_bytes"] = libre
	}
	return hw
}

// memoryStatusEx refleja MEMORYSTATUSEX de kernel32.
type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

func ramTotalBytes() uint64 {
	var m memoryStatusEx
	m.Length = uint32(unsafe.Sizeof(m))
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx")
	if r, _, _ := proc.Call(uintptr(unsafe.Pointer(&m))); r == 0 {
		return 0
	}
	return m.TotalPhys
}

func discoSistema() (total, libre uint64, ok bool) {
	unidad := os.Getenv("SystemDrive")
	if unidad == "" {
		unidad = "C:"
	}
	ptr, err := windows.UTF16PtrFromString(unidad + `\`)
	if err != nil {
		return 0, 0, false
	}
	var libreDisponible, totalBytes, totalLibre uint64
	if err := windows.GetDiskFreeSpaceEx(ptr, &libreDisponible, &totalBytes, &totalLibre); err != nil {
		return 0, 0, false
	}
	return totalBytes, totalLibre, true
}

// volumenBitlocker es la forma que devuelve Get-BitLockerVolume (los campos que
// nos interesan). ProtectionStatus: 1 = protegido/cifrado, 0 = no.
type volumenBitlocker struct {
	MountPoint           string  `json:"MountPoint"`
	ProtectionStatus     int     `json:"ProtectionStatus"`
	EncryptionPercentage float64 `json:"EncryptionPercentage"`
}

// estadoCifrado consulta BitLocker y anota en hw si el disco del sistema esta
// cifrado (compliance). Se apoya en Get-BitLockerVolume de PowerShell: si el
// equipo no tiene BitLocker (p. ej. Windows Home) o el cmdlet no existe, la orden
// falla y simplemente no se anota nada —el panel lo mostrara como "sin datos"—.
func estadoCifrado(ctx context.Context, hw map[string]any) {
	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx2, "powershell.exe",
		"-NoProfile", "-NonInteractive", "-Command",
		"Get-BitLockerVolume -ErrorAction SilentlyContinue | "+
			"Select-Object MountPoint,ProtectionStatus,EncryptionPercentage | ConvertTo-Json -Compress")
	out, err := cmd.Output()
	if err != nil {
		return
	}
	trimmed := bytes.TrimSpace(out)
	if len(trimmed) == 0 {
		return
	}

	// ConvertTo-Json devuelve un objeto si hay un solo volumen y un arreglo si hay
	// varios: se contemplan las dos formas.
	var vols []volumenBitlocker
	if trimmed[0] == '[' {
		_ = json.Unmarshal(trimmed, &vols)
	} else {
		var uno volumenBitlocker
		if json.Unmarshal(trimmed, &uno) == nil {
			vols = []volumenBitlocker{uno}
		}
	}
	if len(vols) == 0 {
		return
	}

	sysDrive := os.Getenv("SystemDrive")
	if sysDrive == "" {
		sysDrive = "C:"
	}
	detalle := make([]map[string]any, 0, len(vols))
	for _, v := range vols {
		protegido := v.ProtectionStatus == 1
		detalle = append(detalle, map[string]any{
			"mount":     v.MountPoint,
			"protected": protegido,
			"percent":   v.EncryptionPercentage,
		})
		if strings.EqualFold(strings.TrimRight(v.MountPoint, `\`), sysDrive) {
			hw["disk_encrypted"] = protegido
		}
	}
	hw["encryption"] = detalle
}
