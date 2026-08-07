package collector

import (
	"testing"
	"time"
)

// La regla clipboard.copia_desde_origen_protegido compara `source_app`. Sin
// aplicacion de origen el evento no es accionable: seria ruido que nadie puede
// investigar.
func TestCopiaSinOrigenNoSeEmite(t *testing.T) {
	m := nuevaMaquinaPortapapeles()

	ev := m.observar(copiaPortapapeles{Bytes: 1024, Momento: time.Now()}, "alert")
	if ev != nil {
		t.Fatal("una copia sin aplicacion de origen no debe emitir evento")
	}
}

// Copiar varias celdas de una hoja de calculo produce una rafaga de cambios de
// portapapeles. Al motor DLP le interesa que hubo extraccion, no cuantas veces
// se pulso Ctrl+C.
func TestRafagaDesdeLaMismaAplicacionSeAgrupa(t *testing.T) {
	m := nuevaMaquinaPortapapeles()
	base := time.Date(2026, 8, 7, 16, 0, 0, 0, time.UTC)

	primera := m.observar(copiaPortapapeles{
		AplicacionOrigen: "excel.exe", Usuario: "jperez", Momento: base,
	}, "alert")
	if primera == nil {
		t.Fatal("la primera copia deberia emitir")
	}

	for i := 1; i <= 5; i++ {
		ev := m.observar(copiaPortapapeles{
			AplicacionOrigen: "excel.exe", Usuario: "jperez",
			Momento: base.Add(time.Duration(i) * 3 * time.Second),
		}, "alert")
		if ev != nil {
			t.Fatalf("la copia %d dentro de la ventana no deberia emitir", i)
		}
	}

	// Pasada la ventana, volver a copiar es un hecho nuevo.
	tarde := m.observar(copiaPortapapeles{
		AplicacionOrigen: "excel.exe", Usuario: "jperez",
		Momento: base.Add(VentanaRepeticionPortapapeles + time.Second),
	}, "alert")
	if tarde == nil {
		t.Fatal("pasada la ventana deberia volver a emitir")
	}
}

func TestAplicacionesDistintasSonEventosDistintos(t *testing.T) {
	m := nuevaMaquinaPortapapeles()
	base := time.Now()

	a := m.observar(copiaPortapapeles{AplicacionOrigen: "excel.exe", Momento: base}, "alert")
	b := m.observar(copiaPortapapeles{AplicacionOrigen: "chrome.exe", Momento: base}, "alert")

	if a == nil || b == nil {
		t.Fatal("copiar desde dos aplicaciones son dos hechos distintos")
	}
}

func TestPayloadDePortapapelesNoLlevaLoCopiado(t *testing.T) {
	m := nuevaMaquinaPortapapeles()

	ev := m.observar(copiaPortapapeles{
		AplicacionOrigen: "excel.exe",
		Bytes:            40960,
		Formato:          "text",
		Usuario:          "jperez",
		Momento:          time.Now(),
	}, "block")

	if ev == nil {
		t.Fatal("deberia emitir")
	}
	p := ev.Payload

	if p["source_app"] != "excel.exe" {
		t.Errorf("source_app: %v", p["source_app"])
	}
	if p["bytes"] != int64(40960) {
		t.Errorf("bytes: %v", p["bytes"])
	}
	if p["format"] != "text" {
		t.Errorf("format: %v", p["format"])
	}
	if p["enforcement"] != "block" {
		t.Errorf("enforcement: %v", p["enforcement"])
	}
	if p["category"] != "ofimatica" {
		t.Errorf("category: %v", p["category"])
	}

	// Saber que salieron 40 KB de la aplicacion de nomina basta para abrir un
	// incidente. Guardar esos 40 KB convertiria a Nortis en un registrador de
	// teclas con base de datos.
	for _, prohibido := range []string{"content", "text", "data", "clipboard", "value"} {
		if _, hay := p[prohibido]; hay {
			t.Errorf("el payload no puede llevar %q", prohibido)
		}
	}
}

// El contrato de telemetria solo admite cuatro formatos; cualquier otro hace que
// la consola descarte el evento entero, en silencio.
func TestFormatoSeNormalizaAlContrato(t *testing.T) {
	validos := map[string]string{
		"text":      "text",
		"image":     "image",
		"file_list": "file_list",
		"other":     "other",
		"":          "other",
		"HTML":      "other",
		"rtf":       "other",
	}

	for entrada, esperado := range validos {
		if got := FormatoValido(entrada); got != esperado {
			t.Errorf("%q -> %q, se esperaba %q", entrada, got, esperado)
		}
	}
}
