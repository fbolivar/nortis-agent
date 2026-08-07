package collector

import (
	"testing"
	"time"
)

func TestRuidoSeDescarta(t *testing.T) {
	ruido := []string{
		`C:\Users\jperez\AppData\Local\Chrome\Cache\f_00123`,
		`C:\Users\jperez\Documents\~$informe.docx`, // bloqueo de Office
		`C:\Users\jperez\Downloads\pelicula.crdownload`,
		`C:\Windows\System32\config\SOFTWARE.LOG1`,
		`C:\Users\jperez\Documents\proyecto\node_modules\react\index.js`,
		`C:\$Recycle.Bin\S-1-5-21\$RABC123.docx`,
		`C:\Users\jperez\Documents\.git\objects\ab\cdef`,
		`E:\algo.tmp`,
	}

	for _, r := range ruido {
		if !esRuido(r) {
			t.Errorf("deberia descartarse como ruido: %s", r)
		}
	}
}

func TestLoQueImportaNoSeDescarta(t *testing.T) {
	reales := []string{
		`C:\Users\jperez\Documents\nomina-agosto.xlsx`,
		`C:\Users\jperez\Desktop\contratos.pdf`,
		`E:\respaldo\base-clientes.csv`,
		`C:\Users\jperez\Downloads\instalador.exe`,
		`D:\Compartido\balance.docx`,
	}

	for _, r := range reales {
		if esRuido(r) {
			t.Errorf("NO deberia descartarse: %s", r)
		}
	}
}

// Guardar en Word produce media docena de escrituras. Sin agrupacion, el
// analista veria cuarenta lineas donde hubo un guardado.
func TestRepeticionSobreElMismoArchivoSeAgrupa(t *testing.T) {
	m := nuevaMaquinaArchivos()
	base := time.Date(2026, 8, 7, 16, 0, 0, 0, time.UTC)
	cambio := cambioArchivo{Ruta: `C:\Users\jperez\Documents\informe.docx`, Operacion: archivoModificado}

	if ev, _ := m.observar(cambio, base); ev == nil {
		t.Fatal("el primer cambio deberia emitir")
	}
	for i := 1; i <= 4; i++ {
		if ev, _ := m.observar(cambio, base.Add(time.Duration(i)*time.Second)); ev != nil {
			t.Fatalf("la repeticion a los %ds no deberia emitir", i)
		}
	}

	// Pasada la ventana, un guardado nuevo si es un hecho nuevo.
	if ev, _ := m.observar(cambio, base.Add(VentanaRepeticion+time.Second)); ev == nil {
		t.Fatal("pasada la ventana deberia volver a emitir")
	}
}

func TestArchivosDistintosNoSeAgrupanEntreSi(t *testing.T) {
	m := nuevaMaquinaArchivos()
	base := time.Date(2026, 8, 7, 16, 0, 0, 0, time.UTC)

	a, _ := m.observar(cambioArchivo{Ruta: `C:\Users\j\Documents\a.xlsx`, Operacion: archivoCreado}, base)
	b, _ := m.observar(cambioArchivo{Ruta: `C:\Users\j\Documents\b.xlsx`, Operacion: archivoCreado}, base)

	if a == nil || b == nil {
		t.Fatal("dos archivos distintos en el mismo instante son dos hechos distintos")
	}
}

// El motor DLP compara `path` contra allowed_paths y `extension` contra
// blocked_extensions. Si faltaran, ninguna de las dos reglas de storage podria
// dispararse.
func TestPayloadLlevaLoQueLasReglasDeStorageNecesitan(t *testing.T) {
	m := nuevaMaquinaArchivos()

	ev, _ := m.observar(cambioArchivo{
		Ruta:       `E:\respaldo\base-clientes.csv`,
		Operacion:  archivoCreado,
		Extraible:  true,
		Usuario:    "jperez",
		TamanoByte: 2048,
	}, time.Now())

	if ev == nil {
		t.Fatal("deberia emitir")
	}
	if ev.Type != "file_created" {
		t.Errorf("tipo: %s", ev.Type)
	}
	if ev.Payload["path"] != `E:\respaldo\base-clientes.csv` {
		t.Errorf("path: %v", ev.Payload["path"])
	}
	if ev.Payload["extension"] != ".csv" {
		t.Errorf("extension: %v", ev.Payload["extension"])
	}
	if ev.Payload["is_removable"] != true {
		t.Error("un archivo que aparece en una unidad extraible tiene que marcarse")
	}
	if ev.Payload["user"] != "jperez" {
		t.Errorf("user: %v", ev.Payload["user"])
	}

	// Nunca contenido: se prueba QUE se movio informacion, no que informacion.
	for _, prohibido := range []string{"content", "contents", "body", "text", "data"} {
		if _, hay := ev.Payload[prohibido]; hay {
			t.Errorf("el payload no puede llevar %q", prohibido)
		}
	}
}

func TestRenombradoConservaLaRutaAnterior(t *testing.T) {
	m := nuevaMaquinaArchivos()

	ev, _ := m.observar(cambioArchivo{
		Ruta:         `E:\nomina.xlsx`,
		RutaAnterior: `C:\Users\jperez\Documents\nomina.xlsx`,
		Operacion:    archivoRenombrado,
		Extraible:    true,
	}, time.Now())

	if ev == nil {
		t.Fatal("deberia emitir")
	}
	// Sin previous_path, mover un archivo a un USB se veria como un archivo que
	// aparecio de la nada: se perderia la prueba de que salio de Documentos.
	if ev.Payload["previous_path"] != `C:\Users\jperez\Documents\nomina.xlsx` {
		t.Errorf("previous_path: %v", ev.Payload["previous_path"])
	}
	if ev.Type != "file_modified" {
		t.Errorf("un renombrado se reporta como modificacion: %s", ev.Type)
	}
}

// Descomprimir un ZIP grande produce miles de escrituras legitimas en segundos.
// Sin tope se comerian el limite de tasa del equipo y dejarian fuera lo que si
// importa.
func TestElCaudalSeAcotaYSeAvisa(t *testing.T) {
	m := nuevaMaquinaArchivos()
	base := time.Date(2026, 8, 7, 16, 0, 0, 0, time.UTC)

	emitidos, recortados := 0, 0
	for i := 0; i < MaxEventosArchivoPorMinuto+50; i++ {
		ev, recorte := m.observar(cambioArchivo{
			Ruta:      `C:\Users\j\Documents\lote\archivo` + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".dat",
			Operacion: archivoCreado,
		}, base)
		if ev != nil {
			emitidos++
		}
		if recorte {
			recortados++
		}
	}

	if emitidos > MaxEventosArchivoPorMinuto {
		t.Fatalf("se emitieron %d, por encima del tope de %d", emitidos, MaxEventosArchivoPorMinuto)
	}
	if recortados == 0 {
		t.Fatal("el recorte tiene que ser visible para poder registrarlo, no silencioso")
	}
}
