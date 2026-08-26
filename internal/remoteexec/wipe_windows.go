//go:build windows

package remoteexec

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// subcarpetasDoc son las carpetas de documentos del usuario que el borrado remoto
// vacia, en los dos idiomas en que Windows las crea.
var subcarpetasDoc = []string{
	"Desktop", "Documents", "Downloads",
	"Escritorio", "Documentos", "Descargas",
}

// EjecutarWipe borra los DATOS del usuario del equipo: el contenido de sus
// carpetas de documentos (Escritorio, Documentos, Descargas, incluidas las de
// OneDrive) y de las unidades extraibles conectadas. Es el borrado para un equipo
// perdido o robado.
//
// ALCANCE ACOTADO Y FIJO por seguridad: nunca toca AppData, Windows, Archivos de
// programa ni el propio Nortis —solo las carpetas donde vive el trabajo de la
// persona—, y el conjunto lo decide el agente, no la consola. Asi, ni una tarea
// firmada puede convertir el wipe en "borra C:\Windows".
func EjecutarWipe(_ context.Context, _ WipePayload) (int, string, error) {
	borrados := 0
	for _, dir := range carpetasAWipe() {
		borrados += borrarContenido(dir)
	}
	return 0, fmt.Sprintf("borrado remoto: %d elementos eliminados de carpetas de datos", borrados), nil
}

// carpetasAWipe devuelve las carpetas cuyo contenido se borra.
func carpetasAWipe() []string {
	var out []string

	unidad := os.Getenv("SystemDrive")
	if unidad == "" {
		unidad = "C:"
	}

	usuarios := unidad + `\Users`
	if entradas, err := os.ReadDir(usuarios); err == nil {
		for _, e := range entradas {
			if !e.IsDir() {
				continue
			}
			switch e.Name() {
			case "Public", "Default", "Default User", "All Users":
				continue
			}
			perfil := filepath.Join(usuarios, e.Name())
			raices := []string{perfil}
			if subs, err := os.ReadDir(perfil); err == nil {
				for _, s := range subs {
					if s.IsDir() && strings.HasPrefix(strings.ToLower(s.Name()), "onedrive") {
						raices = append(raices, filepath.Join(perfil, s.Name()))
					}
				}
			}
			for _, raiz := range raices {
				for _, sub := range subcarpetasDoc {
					p := filepath.Join(raiz, sub)
					if st, err := os.Stat(p); err == nil && st.IsDir() {
						out = append(out, p)
					}
				}
			}
		}
	}

	for _, letra := range unidadesExtraiblesWipe() {
		out = append(out, letra+`\`)
	}
	return out
}

// borrarContenido elimina cada elemento DENTRO de dir (no el dir en si) y devuelve
// cuantos consiguio borrar. Lo que este en uso o protegido simplemente no cae; no
// es un fallo que detenga el resto.
func borrarContenido(dir string) int {
	entradas, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entradas {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err == nil {
			n++
		}
	}
	return n
}

func unidadesExtraiblesWipe() []string {
	mascara, err := windows.GetLogicalDrives()
	if err != nil {
		return nil
	}
	var out []string
	for i := uint(0); i < 26; i++ {
		if mascara&(1<<i) == 0 {
			continue
		}
		letra := string(rune('A'+i)) + ":"
		p, err := windows.UTF16PtrFromString(letra + `\`)
		if err != nil {
			continue
		}
		if windows.GetDriveType(p) == windows.DRIVE_REMOVABLE {
			out = append(out, letra)
		}
	}
	return out
}
