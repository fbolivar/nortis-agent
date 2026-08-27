//go:build windows

package remoteexec

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// EjecutarScan lanza un escaneo de Windows Defender de forma DESACOPLADA: arranca
// el escaneo en un proceso independiente (Start-Process) y vuelve enseguida, sin
// esperar a que termine. Un escaneo completo puede durar horas y bloquear la
// tarea no aporta nada; el resultado (fecha del ultimo escaneo y amenazas) se ve
// en el siguiente inventario de postura. Corre como SYSTEM, que es quien puede
// pedir el escaneo de maquina.
func EjecutarScan(ctx context.Context, p ScanPayload) (int, string, error) {
	tipo := "QuickScan"
	etiqueta := "rapido"
	if p.Type == "full" {
		tipo = "FullScan"
		etiqueta = "completo"
	}

	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Start-Process arranca un powershell hijo que sobrevive a este proceso, asi
	// que el escaneo sigue aunque la tarea ya haya reportado "iniciado".
	arranque := fmt.Sprintf(
		"Start-Process powershell.exe -WindowStyle Hidden -ArgumentList "+
			"'-NoProfile','-NonInteractive','-Command','Start-MpScan -ScanType %s'", tipo)
	cmd := exec.CommandContext(ctx2, "powershell.exe",
		"-NoProfile", "-NonInteractive", "-Command", arranque)
	if out, err := cmd.CombinedOutput(); err != nil {
		return -1, string(out), fmt.Errorf("no se pudo iniciar el escaneo: %w", err)
	}
	return 0, "escaneo " + etiqueta + " iniciado; el resultado aparecera en el proximo inventario", nil
}
