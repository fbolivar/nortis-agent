package enforce

import (
	"path/filepath"
	"strings"
)

// La regla de almacenamiento en modo usuario: DETECTAR y RETIRAR un archivo
// guardado fuera de las carpetas permitidas. No es prevencion real —para eso
// haria falta un driver de kernel— sino remediacion: el archivo llega a
// escribirse y el agente lo retira enseguida a cuarentena. Queda una ventana de
// milisegundos, pero el archivo no persiste en el sitio prohibido.
//
// Se retira a CUARENTENA, no se borra: borrar el trabajo de un usuario es
// irreversible, y un falso positivo destruiria informacion legitima. Mover a una
// carpeta protegida logra el objetivo —el archivo no se queda donde no debe— y
// deja recuperarlo.

// extensionesSensibles acota la remediacion a documentos. Un archivo temporal,
// una imagen de cache o un ejecutable creado fuera de la carpeta permitida NO se
// tocan: la regla persigue fuga de documentos, no interferir con el sistema.
var extensionesSensibles = map[string]bool{
	".doc": true, ".docx": true, ".xls": true, ".xlsx": true, ".ppt": true, ".pptx": true,
	".pdf": true, ".csv": true, ".txt": true, ".rtf": true, ".odt": true, ".ods": true,
	".zip": true, ".rar": true, ".7z": true, ".accdb": true, ".mdb": true, ".sql": true,
	".dwg": true, ".pst": true, ".ost": true,
}

// fragmentosExcluidos son tramos de ruta que NUNCA se remedian, aunque queden
// fuera de la carpeta permitida. Retirar algo de AppData, de Temp, de Windows o
// del propio Nortis romperia el equipo o entraria en bucle. La regla es
// deliberadamente timida: es peor destrozar un equipo que dejar pasar un archivo.
var fragmentosExcluidos = []string{
	`\appdata\`, `\temp\`, `\tmp\`, `\windows\`, `\program files`,
	`\programdata\`, `\$recycle.bin\`, `\system volume information\`,
}

func normRuta(p string) string {
	return strings.ToLower(filepath.Clean(p))
}

// BajoAlguna indica si `ruta` esta dentro de alguna de las `bases`. La
// comparacion normaliza igual que la consola (minusculas, sin barra final) para
// que "D:\Compartido" y "d:\compartido\" coincidan.
func BajoAlguna(ruta string, bases []string) bool {
	r := normRuta(ruta)
	for _, b := range bases {
		nb := normRuta(b)
		if nb == "" {
			continue
		}
		if r == nb || strings.HasPrefix(r, nb+`\`) {
			return true
		}
	}
	return false
}

// DebeCuarentenar decide si un archivo escrito fuera de las carpetas permitidas
// debe retirarse. Conservador por diseño:
//
//   - Sin carpetas permitidas, la regla NO aplica: "sin carpeta seleccionada" no
//     significa "prohibido en todas partes". Invertirlo dejaria al usuario sin
//     poder guardar en cuanto alguien creara un perfil a medio configurar.
//   - Solo tipos de documento; nunca rutas del sistema, de aplicaciones o
//     temporales.
//   - Solo lo que queda FUERA de las carpetas permitidas.
func DebeCuarentenar(ruta string, allowedPaths []string) bool {
	if len(allowedPaths) == 0 {
		return false
	}
	r := normRuta(ruta)
	if !extensionesSensibles[strings.ToLower(filepath.Ext(r))] {
		return false
	}
	for _, frag := range fragmentosExcluidos {
		if strings.Contains(r, frag) {
			return false
		}
	}
	return !BajoAlguna(ruta, allowedPaths)
}
