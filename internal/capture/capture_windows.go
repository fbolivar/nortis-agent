//go:build windows

// Package capture toma una captura de pantalla del usuario interactivo. Existe
// SOLO para la funcion de monitoreo con consentimiento firmado: el servicio no la
// invoca a menos que la politica traiga screenshots=true, y la consola solo envia
// ese campo si el tenant firmo la autorizacion de tratamiento de datos.
package capture

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"

	"github.com/fbolivar/nortis-agent/internal/winsession"
)

// scriptCaptura pinta la pantalla virtual (todos los monitores) a un PNG en el
// %TEMP% del usuario y escribe la ruta. Se ejecuta EN LA SESION DEL USUARIO —el
// agente corre como SYSTEM en la sesion 0 y desde ahi la pantalla esta en negro—.
const scriptCaptura = `Add-Type -AssemblyName System.Windows.Forms,System.Drawing;` +
	`$b=[System.Windows.Forms.SystemInformation]::VirtualScreen;` +
	`$bmp=New-Object System.Drawing.Bitmap $b.Width,$b.Height;` +
	`$g=[System.Drawing.Graphics]::FromImage($bmp);` +
	`$g.CopyFromScreen($b.X,$b.Y,0,0,$b.Size);` +
	`$p=Join-Path $env:TEMP ("nortis-cap-"+[guid]::NewGuid().ToString()+".png");` +
	`$bmp.Save($p,[System.Drawing.Imaging.ImageFormat]::Png);` +
	`$g.Dispose();$bmp.Dispose();Write-Output $p`

// Capturar devuelve el PNG de la pantalla del usuario, o error si no hay sesion
// interactiva accesible (pantalla de bloqueo sin nadie, RDP cerrado, etc.).
func Capturar(ctx context.Context) ([]byte, error) {
	// Sesion del usuario ACTIVO (consola o RDP): desde la sesion 0 la pantalla
	// esta en negro, y mirar solo la consola fallaba en equipos por RDP.
	token, _, err := winsession.TokenUsuarioActivo()
	if err != nil {
		return nil, fmt.Errorf("no hay una sesion de usuario activa que capturar: %w", err)
	}
	defer token.Close()

	cmd := exec.CommandContext(ctx, "powershell.exe",
		"-NoProfile", "-NonInteractive", "-Command", scriptCaptura)
	// Se ejecuta con el token del usuario: asi el proceso ve su escritorio. Sin
	// ventana para no molestar a la persona.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Token:         syscall.Token(token),
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW,
	}

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("la captura fallo: %w", err)
	}
	ruta := strings.TrimSpace(string(out))
	if ruta == "" {
		return nil, fmt.Errorf("la captura no devolvio una ruta")
	}
	defer func() { _ = os.Remove(ruta) }()

	// SYSTEM puede leer el archivo temporal que escribio el proceso del usuario.
	png, err := os.ReadFile(ruta) // #nosec G304 -- la ruta la genera el propio script, no una entrada externa
	if err != nil {
		return nil, fmt.Errorf("no se pudo leer la captura: %w", err)
	}
	return png, nil
}
