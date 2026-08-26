//go:build windows

package remoteexec

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// clavesUninstall son las vistas del registro donde Windows anota los programas
// instalados a nivel de maquina (64 y 32 bits).
var clavesUninstall = []struct {
	raiz registry.Key
	ruta string
}{
	{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
	{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
}

// EjecutarUninstall busca el programa por su DisplayName exacto en el registro y
// ejecuta su desinstalacion en silencio. Prefiere QuietUninstallString; para MSI
// (clave con GUID) usa `msiexec /x {GUID} /quiet`; en ultimo caso el
// UninstallString tal cual (best-effort: algunos instaladores no traen modo
// silencioso). Corre como SYSTEM, que basta para las instalaciones de maquina.
func EjecutarUninstall(ctx context.Context, p UninstallPayload) (int, string, error) {
	objetivo := strings.TrimSpace(p.Name)

	for _, c := range clavesUninstall {
		raiz, err := registry.OpenKey(c.raiz, c.ruta, registry.READ)
		if err != nil {
			continue
		}
		nombres, _ := raiz.ReadSubKeyNames(-1)
		_ = raiz.Close()

		for _, n := range nombres {
			sub, err := registry.OpenKey(c.raiz, c.ruta+`\`+n, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			display, _, _ := sub.GetStringValue("DisplayName")
			quiet, _, _ := sub.GetStringValue("QuietUninstallString")
			ustr, _, _ := sub.GetStringValue("UninstallString")
			_ = sub.Close()

			if !strings.EqualFold(strings.TrimSpace(display), objetivo) {
				continue
			}

			var cmd *exec.Cmd
			switch {
			case strings.TrimSpace(quiet) != "":
				cmd = exec.CommandContext(ctx, "cmd.exe", "/c", quiet)
			case strings.HasPrefix(n, "{") && strings.HasSuffix(n, "}"):
				cmd = exec.CommandContext(ctx, "msiexec.exe", "/x", n, "/quiet", "/norestart")
			case strings.TrimSpace(ustr) != "":
				cmd = exec.CommandContext(ctx, "cmd.exe", "/c", ustr)
			default:
				return -1, "", fmt.Errorf("el programa %q no tiene comando de desinstalacion", objetivo)
			}
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}

			out, err := cmd.CombinedOutput()
			if err != nil {
				return -1, string(out), fmt.Errorf("la desinstalacion de %q fallo: %w", objetivo, err)
			}
			return 0, "programa desinstalado: " + objetivo, nil
		}
	}
	return -1, "", fmt.Errorf("no se encontro el programa %q instalado en el equipo", objetivo)
}
