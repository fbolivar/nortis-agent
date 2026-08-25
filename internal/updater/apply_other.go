//go:build !windows

package updater

import "errors"

// Fuera de Windows no hay MSI que aplicar. El paquete compila en otras
// plataformas para que la logica portable —comparacion de version, descarga y
// verificacion de hash— se pruebe en CI sin un runner de Windows.
func aplicarMSI(string) error {
	return errors.New("la auto-actualizacion por MSI solo esta disponible en Windows")
}
