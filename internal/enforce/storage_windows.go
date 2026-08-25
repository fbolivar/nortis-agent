//go:build windows

package enforce

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Cuarentenar retira un archivo a la carpeta de cuarentena. Intenta un renombrado
// (instantaneo, mismo volumen) y, si falla porque el origen esta en otro volumen
// —tipico de un USB—, copia y borra el original.
//
// El nombre en cuarentena lleva una marca de tiempo para no pisar dos archivos
// que se llamen igual. Devuelve la ruta final, para dejarla en el evento.
func Cuarentenar(ruta, dirCuarentena string) (string, error) {
	if err := os.MkdirAll(dirCuarentena, 0o700); err != nil {
		return "", err
	}
	destino := filepath.Join(dirCuarentena,
		fmt.Sprintf("%d_%s", time.Now().UnixNano(), filepath.Base(ruta)))

	if err := os.Rename(ruta, destino); err == nil {
		return destino, nil
	}
	// Rename entre volumenes falla: copiar y retirar el original.
	if err := copiarArchivo(ruta, destino); err != nil {
		return "", err
	}
	if err := os.Remove(ruta); err != nil {
		return "", fmt.Errorf("copiado a cuarentena pero el original no se pudo retirar: %w", err)
	}
	return destino, nil
}

func copiarArchivo(origen, destino string) error {
	in, err := os.Open(origen) // #nosec G304 -- la ruta la reporta el vigilante del sistema de archivos, no un usuario
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := os.Create(destino) // #nosec G304 -- destino es una ruta fija bajo el directorio del agente
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
