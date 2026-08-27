//go:build windows

package remoteexec

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// EjecutarAccountAction aplica una accion sobre una cuenta local. La validacion
// (incluida la lista de cuentas protegidas) ya paso en ParseAccountAction; aqui
// solo se ejecuta. Todo va por `net`/`logoff`, disponibles en cualquier Windows.
func EjecutarAccountAction(ctx context.Context, p AccountActionPayload) (int, string, error) {
	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Para operar con `net user` se usa el nombre corto (sin "EQUIPO\").
	target := p.Target
	if i := strings.LastIndex(target, `\`); i >= 0 {
		target = target[i+1:]
	}

	switch p.Action {
	case "disable":
		return correr(ctx2, "net", "user", target, "/active:no")
	case "enable":
		return correr(ctx2, "net", "user", target, "/active:yes")
	case "delete":
		return correr(ctx2, "net", "user", target, "/delete")
	case "logoff":
		return cerrarSesion(ctx2, target)
	default:
		return -1, "", fmt.Errorf("accion no soportada: %s", p.Action)
	}
}

// cerrarSesion cierra la sesion del usuario indicado. Resuelve el id de sesion
// con `quser` (tolerante al idioma: se busca la fila cuyo primer campo coincide
// con el usuario y se toma el primer entero de la linea como id) y llama a
// `logoff <id>`.
func cerrarSesion(ctx context.Context, usuario string) (int, string, error) {
	out, _ := exec.CommandContext(ctx, "quser").CombinedOutput()
	var id string
	for _, linea := range strings.Split(string(out), "\n") {
		campos := strings.Fields(linea)
		if len(campos) == 0 {
			continue
		}
		// El nombre de usuario es el primer campo (puede llevar '>' delante en la
		// sesion propia). Se normaliza quitando ese prefijo.
		nombre := strings.TrimPrefix(campos[0], ">")
		if !strings.EqualFold(nombre, usuario) {
			continue
		}
		for _, c := range campos {
			if esEntero(c) {
				id = c
				break
			}
		}
		break
	}
	if id == "" {
		return 0, "el usuario no tiene una sesion activa", nil
	}
	code, o, err := correr(ctx, "logoff", id)
	if err != nil {
		return code, o, err
	}
	return 0, "sesion de " + usuario + " cerrada (id " + id + ")", nil
}

func esEntero(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// EjecutarHarden activa las protecciones pedidas. Al activar el firewall se
// añade PRIMERO una regla de permiso explicita para RDP (3389), de modo que
// encender el cortafuegos no corte la sesion remota del administrador.
func EjecutarHarden(ctx context.Context, p HardenPayload) (int, string, error) {
	ctx2, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	var hechos []string
	for _, t := range p.Targets {
		switch t {
		case "firewall":
			// Salvaguarda: garantizar RDP antes de encender el firewall.
			_, _, _ = correr(ctx2, "netsh", "advfirewall", "firewall", "add", "rule",
				"name=Nortis-RDP", "dir=in", "action=allow", "protocol=TCP", "localport=3389")
			if code, o, err := correr(ctx2, "netsh", "advfirewall", "set", "allprofiles", "state", "on"); err != nil {
				return code, o, fmt.Errorf("no se pudo activar el firewall: %w", err)
			}
			hechos = append(hechos, "firewall activado (RDP preservado)")
		case "defender":
			if code, o, err := correr(ctx2, "powershell.exe", "-NoProfile", "-NonInteractive",
				"-Command", "Set-MpPreference -DisableRealtimeMonitoring $false"); err != nil {
				return code, o, fmt.Errorf("no se pudo activar Defender: %w", err)
			}
			hechos = append(hechos, "proteccion en tiempo real activada")
		}
	}
	return 0, strings.Join(hechos, "; "), nil
}

// puertosLaterales son los puertos de movimiento lateral y exfiltracion interna
// que el aislamiento corta HACIA y DESDE la red local. NO se toca la salida a
// internet ni el gateway, asi la linea de vida del agente (HTTPS 443 al cloud)
// queda intacta: es IMPOSIBLE perder el agente aislando.
var puertosLaterales = []struct {
	proto  string
	puerto string
	nombre string
}{
	{"TCP", "445", "SMB"},
	{"TCP", "139", "NetBIOS-SSN"},
	{"UDP", "137", "NetBIOS-NS"},
	{"UDP", "138", "NetBIOS-DGM"},
	{"TCP", "135", "RPC"},
	{"TCP", "5985", "WinRM"},
	{"TCP", "5986", "WinRM-S"},
}

// reglaIso genera el nombre unico de una regla de aislamiento por puerto/direccion.
func reglaIso(nombre, dir string) string {
	return "Nortis-Iso-" + nombre + "-" + dir
}

// EjecutarAislamiento activa o revierte la contencion de red. Al activar añade
// reglas que BLOQUEAN los puertos de movimiento lateral (SMB, NetBIOS, RPC,
// WinRM) hacia y desde la subred local (remoteip=LocalSubnet), y se asegura de
// que el firewall este encendido para que apliquen. NO cambia la politica de
// salida por defecto (queda en allowoutbound), asi el agente y el resto de la
// salida a internet siguen funcionando. Al revertir borra esas reglas.
func EjecutarAislamiento(ctx context.Context, p IsolatePayload) (int, string, error) {
	ctx2, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	if p.Enable {
		// Preservar RDP explicitamente por si el firewall pasa de apagado a
		// encendido (evita cortar la sesion del administrador).
		_, _, _ = correr(ctx2, "netsh", "advfirewall", "firewall", "add", "rule",
			"name="+reglaIso("RDP", "in"), "dir=in", "action=allow", "protocol=TCP", "localport=3389")

		// La salida por defecto se deja en allowoutbound: la linea de vida no se toca.
		_, _, _ = correr(ctx2, "netsh", "advfirewall", "set", "allprofiles",
			"firewallpolicy", "blockinbound,allowoutbound")
		if code, o, err := correr(ctx2, "netsh", "advfirewall", "set", "allprofiles", "state", "on"); err != nil {
			return code, o, err
		}

		for _, pl := range puertosLaterales {
			for _, dir := range []string{"in", "out"} {
				portArg := "localport=" + pl.puerto
				if dir == "out" {
					portArg = "remoteport=" + pl.puerto
				}
				_, _, _ = correr(ctx2, "netsh", "advfirewall", "firewall", "add", "rule",
					"name="+reglaIso(pl.nombre, dir), "dir="+dir, "action=block",
					"protocol="+pl.proto, portArg, "remoteip=LocalSubnet")
			}
		}
		return 0, "equipo contenido: cortado el movimiento lateral en la LAN (SMB/NetBIOS/RPC/WinRM); internet, RDP y el agente siguen activos", nil
	}

	// Revertir: borrar todas las reglas de aislamiento.
	for _, pl := range puertosLaterales {
		for _, dir := range []string{"in", "out"} {
			_, _, _ = correr(ctx2, "netsh", "advfirewall", "firewall", "delete", "rule", "name="+reglaIso(pl.nombre, dir))
		}
	}
	_, _, _ = correr(ctx2, "netsh", "advfirewall", "firewall", "delete", "rule", "name="+reglaIso("RDP", "in"))
	return 0, "contencion retirada; el equipo vuelve a comunicarse con la LAN", nil
}

// correr ejecuta un comando y devuelve exit code y salida combinada.
func correr(ctx context.Context, nombre string, args ...string) (int, string, error) {
	cmd := exec.CommandContext(ctx, nombre, args...)
	out, err := cmd.CombinedOutput()
	code := 0
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	} else if err != nil {
		code = -1
	}
	if code != 0 && err == nil {
		err = fmt.Errorf("%s devolvio codigo %d", nombre, code)
	}
	return code, strings.TrimSpace(string(out)), err
}
