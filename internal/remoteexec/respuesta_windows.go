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

// reglasAislamiento son las excepciones que se mantienen abiertas durante el
// aislamiento. HTTPS de salida es la LINEA DE VIDA: mantiene al agente
// reportando, asi el aislamiento se puede revertir desde la consola.
var reglasAislamiento = []struct {
	nombre string
	args   []string
}{
	{"Nortis-Iso-DNS", []string{"dir=out", "action=allow", "protocol=UDP", "remoteport=53"}},
	{"Nortis-Iso-HTTPS", []string{"dir=out", "action=allow", "protocol=TCP", "remoteport=443"}},
	{"Nortis-Iso-RDP", []string{"dir=in", "action=allow", "protocol=TCP", "localport=3389"}},
}

// EjecutarAislamiento activa o revierte la cuarentena de red. Al activar: se
// añaden las reglas de excepcion, se pone la politica por defecto en bloquear
// entrada y salida y se enciende el firewall. Al revertir: se borran las reglas
// y se restaura la politica por defecto de Windows (bloquear entrada, permitir
// salida). NOTA: revertir deja el firewall ENCENDIDO (mas seguro que apagarlo a
// ciegas); si el equipo lo tenia apagado, se indica para que el operador decida.
func EjecutarAislamiento(ctx context.Context, p IsolatePayload) (int, string, error) {
	ctx2, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	if p.Enable {
		for _, r := range reglasAislamiento {
			args := append([]string{"advfirewall", "firewall", "add", "rule", "name=" + r.nombre}, r.args...)
			_, _, _ = correr(ctx2, "netsh", args...)
		}
		if code, o, err := correr(ctx2, "netsh", "advfirewall", "set", "allprofiles",
			"firewallpolicy", "blockinbound,blockoutbound"); err != nil {
			return code, o, fmt.Errorf("no se pudo fijar la politica de bloqueo: %w", err)
		}
		if code, o, err := correr(ctx2, "netsh", "advfirewall", "set", "allprofiles", "state", "on"); err != nil {
			return code, o, err
		}
		return 0, "equipo aislado (solo DNS, HTTPS de salida y RDP quedan abiertos)", nil
	}

	// Revertir.
	for _, r := range reglasAislamiento {
		_, _, _ = correr(ctx2, "netsh", "advfirewall", "firewall", "delete", "rule", "name="+r.nombre)
	}
	if code, o, err := correr(ctx2, "netsh", "advfirewall", "set", "allprofiles",
		"firewallpolicy", "blockinbound,allowoutbound"); err != nil {
		return code, o, fmt.Errorf("no se pudo restaurar la politica: %w", err)
	}
	return 0, "aislamiento retirado; politica por defecto restaurada (firewall queda encendido)", nil
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
