//go:build windows

// Package notify muestra un aviso corporativo en la pantalla del usuario.
//
// El servicio corre en la sesion 0, aislada del escritorio; un MessageBox lanzado
// desde ahi no lo veria nadie. Por eso quien llama a Mostrar es un proceso que el
// servicio arranca DENTRO de la sesion del usuario (con su token), igual que el
// vigilante del portapapeles. Aqui solo se dibuja la ventana.
package notify

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32          = windows.NewLazySystemDLL("user32.dll")
	procMessageBoxW = user32.NewProc("MessageBoxW")
)

const (
	mbOK            = 0x00000000
	mbIconWarning   = 0x00000030
	mbSetForeground = 0x00010000
	mbTopmost       = 0x00040000
)

// Mostrar dibuja un aviso modal con titulo y mensaje. Vuelve cuando el usuario
// lo cierra; el proceso que lo alberga es efimero y muere con el.
func Mostrar(titulo, mensaje string) error {
	t, err := windows.UTF16PtrFromString(titulo)
	if err != nil {
		return err
	}
	m, err := windows.UTF16PtrFromString(mensaje)
	if err != nil {
		return err
	}
	// #nosec G103 -- MessageBoxW exige punteros a cadenas UTF-16; es la firma nativa de Win32
	_, _, _ = procMessageBoxW.Call(
		0,
		uintptr(unsafe.Pointer(m)),
		uintptr(unsafe.Pointer(t)),
		mbOK|mbIconWarning|mbTopmost|mbSetForeground,
	)
	return nil
}
