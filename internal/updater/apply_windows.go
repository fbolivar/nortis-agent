//go:build windows

package updater

import (
	"fmt"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// aplicarMSI lanza el instalador en silencio. El MSI trae el mismo UpgradeCode
// que el instalado, asi que Windows Installer hace una actualizacion en sitio:
// detiene el servicio, reemplaza el binario y lo vuelve a arrancar.
//
// Se lanza DESACOPLADO (no como hijo que muera con nosotros): a mitad de la
// actualizacion, el propio MSI detiene este servicio —y con el, este proceso—,
// asi que msiexec tiene que sobrevivir a nuestra muerte para terminar el trabajo.
// Como el servicio corre como SYSTEM, y en el DACL endurecido SYSTEM conserva el
// control del servicio, la parada durante la actualizacion es legitima y no
// choca con la proteccion anti-manipulacion.
func aplicarMSI(ruta string) error {
	cmd := exec.Command("msiexec.exe", "/i", ruta, "/qn", "/norestart")
	// DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP: msiexec no queda atado a la
	// consola ni al ciclo de vida del servicio que lo lanza.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("no se pudo lanzar msiexec: %w", err)
	}
	// No se espera (cmd.Wait): el MSI nos detendra antes de que termine. Se suelta
	// el proceso a proposito.
	return nil
}
