//go:build windows

package remoteexec

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// EjecutarKill termina todos los procesos cuyo ejecutable coincide con Name.
// El agente corre como SYSTEM, asi que puede cerrar procesos del usuario. Se
// compara por nombre exacto (insensible a mayusculas), p. ej. "anydesk.exe".
func EjecutarKill(_ context.Context, p KillPayload) (int, string, error) {
	objetivo := strings.ToLower(strings.TrimSpace(p.Name))

	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return -1, "", fmt.Errorf("no se pudieron enumerar los procesos: %w", err)
	}
	defer func() { _ = windows.CloseHandle(snap) }()

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snap, &entry); err != nil {
		return -1, "", fmt.Errorf("Process32First: %w", err)
	}

	muertos := 0
	for {
		exe := strings.ToLower(windows.UTF16ToString(entry.ExeFile[:]))
		if exe == objetivo {
			if h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, entry.ProcessID); err == nil {
				if windows.TerminateProcess(h, 1) == nil {
					muertos++
				}
				_ = windows.CloseHandle(h)
			}
		}
		if err := windows.Process32Next(snap, &entry); err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				break
			}
			break
		}
	}
	return 0, fmt.Sprintf("terminados %d proceso(s) '%s'", muertos, p.Name), nil
}
