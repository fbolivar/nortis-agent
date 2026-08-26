package enforce

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// RestaurarCuarentena devuelve un archivo retirado a su ruta original. Lo ordena
// la consola tras revisar el incidente. Recrea la carpeta destino si hiciera
// falta (pudo borrarse mientras el archivo estaba en cuarentena).
func RestaurarCuarentena(dirCuarentena, quarantineID, rutaOriginal string) error {
	if err := validarID(quarantineID); err != nil {
		return err
	}
	origen := filepath.Join(dirCuarentena, quarantineID)
	if err := os.MkdirAll(filepath.Dir(rutaOriginal), 0o750); err != nil {
		return err
	}
	return os.Rename(origen, rutaOriginal)
}

// BorrarCuarentena elimina definitivamente un archivo de la cuarentena.
func BorrarCuarentena(dirCuarentena, quarantineID string) error {
	if err := validarID(quarantineID); err != nil {
		return err
	}
	return os.Remove(filepath.Join(dirCuarentena, quarantineID))
}

// validarID rechaza un identificador que no sea un nombre de archivo simple. Es
// la defensa contra un valor con separadores o ".." que, unido a la carpeta de
// cuarentena, saldria de ella y tocaria un archivo cualquiera del sistema: la
// consola encarga la accion, pero el agente no confia ciegamente en la ruta.
func validarID(quarantineID string) error {
	if quarantineID == "" || quarantineID != filepath.Base(quarantineID) ||
		strings.ContainsAny(quarantineID, `/\`) || strings.Contains(quarantineID, "..") {
		return fmt.Errorf("identificador de cuarentena invalido: %q", quarantineID)
	}
	return nil
}

// RetencionCuarentena es cuanto se conserva un archivo retirado antes de
// borrarlo. Es la respuesta a "cuanto tiempo y que se hace": se guarda como
// evidencia un tiempo razonable —por si hubo que revisarlo o restaurarlo— y
// luego se purga, para que la cuarentena no crezca sin fin en el disco del
// equipo. 30 dias cubre el ciclo de revision de un incidente sin acumular.
const RetencionCuarentena = 30 * 24 * time.Hour

// PurgarCuarentena borra de la carpeta de cuarentena los archivos cuya ultima
// modificacion es anterior a `retencion`. Devuelve cuantos borro. Tolera que la
// carpeta aun no exista (nunca se cuarentenó nada).
func PurgarCuarentena(dir string, retencion time.Duration, ahora time.Time) (int, error) {
	entradas, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}

	limite := ahora.Add(-retencion)
	borrados := 0
	for _, e := range entradas {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(limite) {
			if err := os.Remove(filepath.Join(dir, e.Name())); err == nil {
				borrados++
			}
		}
	}
	return borrados, nil
}

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

// VentanaGraciaRestauro es cuanto ignora el agente una ruta recien restaurada
// antes de volver a considerarla para cuarentena. Sin esta gracia, restaurar un
// archivo mientras su clase sigue vigilada en modo cuarentena lo re-cuarentena al
// instante (bucle): el administrador decidio devolverlo, y esa decision debe
// sostenerse el tiempo suficiente para que el evento de la restauracion pase sin
// dispararla. 5 minutos cubre de sobra el procesamiento del evento sin abrir una
// ventana larga en la que un archivo realmente nuevo en esa ruta pasaria libre.
const VentanaGraciaRestauro = 5 * time.Minute

// RegistroRestauros recuerda las rutas restauradas hace poco para no volver a
// cuarentenarlas de inmediato. Es seguro para uso concurrente: lo escribe el
// ejecutor de comandos y lo lee el vigilante de archivos, en goroutines distintas.
type RegistroRestauros struct {
	mu    sync.Mutex
	hasta map[string]time.Time
}

// NuevoRegistroRestauros crea un registro vacio.
func NuevoRegistroRestauros() *RegistroRestauros {
	return &RegistroRestauros{hasta: map[string]time.Time{}}
}

// Marcar anota que `ruta` se acaba de restaurar: se ignorara para cuarentena
// hasta dentro de `ventana`. Se normaliza igual que el resto de comparaciones de
// ruta para que coincida con lo que ve el vigilante.
func (r *RegistroRestauros) Marcar(ruta string, ventana time.Duration, ahora time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hasta[normRuta(ruta)] = ahora.Add(ventana)
}

// Reciente indica si `ruta` se restauro dentro de la ventana de gracia. De paso
// purga las entradas ya vencidas para que el mapa no crezca sin fin.
func (r *RegistroRestauros) Reciente(ruta string, ahora time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, exp := range r.hasta {
		if ahora.After(exp) {
			delete(r.hasta, k)
		}
	}
	exp, ok := r.hasta[normRuta(ruta)]
	return ok && ahora.Before(exp)
}

// RutaRemediable indica si una ruta puede retirarse a cuarentena CON SEGURIDAD:
// nunca carpetas del sistema, temporales, de aplicaciones ni del propio Nortis.
// Retirar algo de ahi romperia el equipo o entraria en bucle. Es la guarda comun
// a toda remediacion —por carpeta no autorizada o por clase de dato vigilada—:
// es peor destrozar un equipo que dejar pasar un archivo.
func RutaRemediable(ruta string) bool {
	r := normRuta(ruta)
	for _, frag := range fragmentosExcluidos {
		if strings.Contains(r, frag) {
			return false
		}
	}
	return true
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
	if !RutaRemediable(ruta) {
		return false
	}
	return !BajoAlguna(ruta, allowedPaths)
}
