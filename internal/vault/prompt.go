package vault

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// LeerLinea muestra un prompt y lee una linea CON eco. Es para respuestas que no
// son secretas (opcion de menu, rutas). Usa el mismo lector sin bufer que las
// contrasenas, de modo que en el flujo interactivo no hay dos mecanismos de
// lectura que se pisen (un bufer consumiria por adelantado la linea siguiente).
func LeerLinea(prompt string) (string, error) {
	if prompt != "" {
		fmt.Print(prompt)
	}
	return leerLineaCruda()
}

// leerLineaCruda lee una linea de stdin byte a byte, sin bufer, deteniendose en el
// salto de linea. No consume mas alla de la linea, asi que varias lecturas
// consecutivas (p. ej. contrasena y su confirmacion) funcionan igual por consola
// que por tuberia.
func leerLineaCruda() (string, error) {
	var sb strings.Builder
	var b [1]byte
	for {
		n, err := os.Stdin.Read(b[:])
		if n > 0 {
			c := b[0] // #nosec G602 -- b es un arreglo de tamaño 1; el indice 0 siempre existe
			switch c {
			case '\n':
				return sb.String(), nil
			case '\r':
				// se ignora el retorno de carro (fin de linea de Windows)
			default:
				sb.WriteByte(c)
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return sb.String(), nil
			}
			return sb.String(), err
		}
	}
}
