//go:build windows

package vault

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// LeerPassword pide una contrasena por consola SIN eco (no se ve al teclear). Se
// lee byte a byte desde stdin (sin bufer) para no consumir de mas: asi funciona
// igual escribiendo en la consola que recibiendo la entrada por una tuberia.
func LeerPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	h := windows.Handle(os.Stdin.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err == nil {
		_ = windows.SetConsoleMode(h, mode&^windows.ENABLE_ECHO_INPUT)
		defer func() { _ = windows.SetConsoleMode(h, mode) }()
	}
	s, err := leerLineaCruda()
	fmt.Println()
	return s, err
}
