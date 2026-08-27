//go:build windows

package vault

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// LeerPassword pide una contrasena por consola SIN eco (no se ve al teclear).
func LeerPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	h := windows.Handle(os.Stdin.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err == nil {
		_ = windows.SetConsoleMode(h, mode&^windows.ENABLE_ECHO_INPUT)
		defer func() { _ = windows.SetConsoleMode(h, mode) }()
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	fmt.Println()
	return strings.TrimRight(line, "\r\n"), err
}
