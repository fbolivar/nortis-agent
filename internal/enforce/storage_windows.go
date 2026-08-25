//go:build windows

package enforce

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// reintentosBloqueo y esperaBloqueo controlan cuanto se insiste cuando el archivo
// esta bloqueado. En el instante en que se detecta, la aplicacion que lo escribio
// (la copia, el Guardar como) suele tenerlo aun abierto; el bloqueo se libera en
// menos de un segundo. Se reintenta hasta ~3 s, que cubre de sobra el caso comun
// sin colgar la vigilancia.
const (
	reintentosBloqueo = 12
	esperaBloqueo     = 250 * time.Millisecond
)

// Cuarentenar retira un archivo a la carpeta de cuarentena.
//
// Prefiere un RENOMBRADO (atomico, instantaneo, sin dejar copia). El archivo casi
// siempre esta bloqueado el primer instante —quien lo escribio lo tiene abierto—,
// asi que se reintenta: el bloqueo es transitorio. Solo si el renombrado falla de
// forma persistente por estar en otro volumen (un USB) se recurre a copiar y
// borrar, tambien con reintentos para el borrado del original.
func Cuarentenar(ruta, dirCuarentena string) (string, error) {
	if err := os.MkdirAll(dirCuarentena, 0o700); err != nil {
		return "", err
	}
	destino := filepath.Join(dirCuarentena,
		fmt.Sprintf("%d_%s", time.Now().UnixNano(), filepath.Base(ruta)))

	var err error
	for intento := 0; intento < reintentosBloqueo; intento++ {
		if err = os.Rename(ruta, destino); err == nil {
			return destino, nil
		}
		// Si el original ya no esta (lo movio otro evento del mismo archivo), no
		// es un fallo: alguien mas gano la carrera y el objetivo ya se cumplio.
		if os.IsNotExist(err) {
			return "", err
		}
		time.Sleep(esperaBloqueo)
	}

	// Renombrado imposible tras insistir: casi seguro es otro volumen. Copiar y
	// retirar el original, reintentando el borrado por si sigue bloqueado.
	if cerr := copiarArchivo(ruta, destino); cerr != nil {
		return "", cerr
	}
	for intento := 0; intento < reintentosBloqueo; intento++ {
		if err = os.Remove(ruta); err == nil {
			return destino, nil
		}
		if os.IsNotExist(err) {
			return destino, nil
		}
		time.Sleep(esperaBloqueo)
	}
	return "", fmt.Errorf("copiado a cuarentena pero el original no se pudo retirar: %w", err)
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
