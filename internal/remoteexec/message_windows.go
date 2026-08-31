//go:build windows

package remoteexec

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"

	"github.com/fbolivar/nortis-agent/internal/winsession"
)

// MostrarAviso muestra un aviso en la pantalla del usuario. Reutiliza el
// subcomando `notify` del propio agente, lanzado EN LA SESION DEL USUARIO ACTIVO
// (consola o RDP) con su token: desde la sesion 0 (SYSTEM) el aviso no se veria.
// Lo usan tanto la tarea `message` como el coaching en el momento (p. ej. cuando
// se retira un archivo en claro de un USB).
func MostrarAviso(ctx context.Context, titulo, cuerpo string) error {
	token, _, err := winsession.TokenUsuarioActivo()
	if err != nil {
		return fmt.Errorf("no hay un usuario con sesion activa al que avisar: %w", err)
	}
	defer token.Close()

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if titulo == "" {
		titulo = "Nortis"
	}

	cmd := exec.CommandContext(ctx, exe, "notify", "-title", titulo, "-message", cuerpo)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Token:         syscall.Token(token),
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW,
	}
	// Start y no Run: el aviso vive en la sesion del usuario hasta que lo cierre;
	// no hay que bloquear esperando a que lo lea.
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("no se pudo mostrar el aviso: %w", err)
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

// EjecutarMensaje muestra un aviso (tarea `message`).
func EjecutarMensaje(ctx context.Context, p MessagePayload) (int, string, error) {
	if err := MostrarAviso(ctx, p.Title, p.Body); err != nil {
		return -1, "", err
	}
	return 0, "aviso enviado al usuario", nil
}
