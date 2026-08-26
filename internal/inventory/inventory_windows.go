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
	"os"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/fbolivar/nortis-agent/internal/contract"
)

// Recolectar devuelve el hardware (mapa suelto) y la lista de software instalado.
func Recolectar() (map[string]any, []contract.SoftwareItem) {
	return recolectarHardware(), recolectarSoftware()
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
		"cpu_cores": runtime.NumCPU(),
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
