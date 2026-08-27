//go:build !windows

package vault

import "fmt"

// LeerPassword pide una contrasena por consola. Fuera de Windows se lee en claro
// (fallback de desarrollo); el binario de produccion es de Windows y oculta el eco.
func LeerPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	return leerLineaCruda()
}
