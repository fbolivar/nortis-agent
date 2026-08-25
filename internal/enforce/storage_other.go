//go:build !windows

package enforce

import "errors"

// Fuera de Windows no hay cuarentena que aplicar. El stub deja compilable la
// logica de decision (DebeCuarentenar), que es portable y esta cubierta por
// pruebas, sin un runner de Windows.
func Cuarentenar(string, string) (string, error) {
	return "", errors.New("la cuarentena de archivos solo esta disponible en Windows")
}
