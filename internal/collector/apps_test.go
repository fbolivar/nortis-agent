package collector

import (
	"fmt"
	"testing"
)

func TestAppNuevaEmiteUnSoloEvento(t *testing.T) {
	m := nuevaMaquinaApps()

	ev, _ := m.observar([]proceso{
		{PID: 10, Exe: "EXCEL.EXE", SessionID: 1, Usuario: "ana", Ruta: `C:\Office\EXCEL.EXE`},
	}, t0)

	if len(ev) != 1 {
		t.Fatalf("se esperaba 1 evento, se obtuvieron %d", len(ev))
	}
	p := ev[0].Payload
	if p["app"] != "EXCEL.EXE" {
		t.Errorf("app incorrecta: %v", p["app"])
	}
	if p["category"] != "ofimatica" {
		t.Errorf("categoria incorrecta: %v", p["category"])
	}
	if p["executable_path"] != `C:\Office\EXCEL.EXE` || p["user"] != "ana" {
		t.Errorf("payload incompleto: %v", p)
	}
}

// El caso que justifica agrupar por nombre y no por PID: Chrome levanta un
// proceso por pestaña y por PID el reporte seria una lista de veinte "Chrome".
func TestVariosProcesosDeLaMismaAppSonUnEvento(t *testing.T) {
	m := nuevaMaquinaApps()

	var procesos []proceso
	for i := range 20 {
		procesos = append(procesos, proceso{PID: uint32(100 + i), Exe: "chrome.exe", SessionID: 1})
	}

	ev, _ := m.observar(procesos, t0)
	if len(ev) != 1 {
		t.Fatalf("se esperaba 1 evento para 20 procesos de Chrome, se obtuvieron %d", len(ev))
	}
}

func TestAppYaVistaNoSeRepite(t *testing.T) {
	m := nuevaMaquinaApps()
	p := []proceso{{PID: 10, Exe: "chrome.exe", SessionID: 1}}
	m.observar(p, t0)

	for i := range 5 {
		if ev, _ := m.observar(p, t0); len(ev) != 0 {
			t.Fatalf("sondeo %d repitio la app: %v", i, ev)
		}
	}
}

// Cerrar y volver a abrir SI es una apertura nueva: sin olvidar el estado, el
// reporte diria que la persona abrio Excel una vez en todo el mes.
func TestReabrirVuelveAEmitir(t *testing.T) {
	m := nuevaMaquinaApps()
	p := []proceso{{PID: 10, Exe: "winword.exe", SessionID: 1}}
	m.observar(p, t0)
	m.observar(nil, t0) // se cerro

	if ev, _ := m.observar(p, t0); len(ev) != 1 {
		t.Fatalf("reabrir deberia emitir 1 evento, se obtuvieron %d", len(ev))
	}
}

func TestLaMismaAppEnDosSesionesSonDosEventos(t *testing.T) {
	m := nuevaMaquinaApps()

	ev, _ := m.observar([]proceso{
		{PID: 10, Exe: "chrome.exe", SessionID: 1, Usuario: "ana"},
		{PID: 11, Exe: "chrome.exe", SessionID: 2, Usuario: "beto"},
	}, t0)

	if len(ev) != 2 {
		t.Fatalf("se esperaban 2 eventos (una por usuario), se obtuvieron %d", len(ev))
	}
}

func TestRuidoDelSistemaSeDescarta(t *testing.T) {
	m := nuevaMaquinaApps()

	ev, _ := m.observar([]proceso{
		{PID: 10, Exe: "RuntimeBroker.exe", SessionID: 1},
		{PID: 11, Exe: "dwm.exe", SessionID: 1},
		{PID: 12, Exe: "nortis-agent.exe", SessionID: 1},
		{PID: 13, Exe: "msedgewebview2.exe", SessionID: 1},
		{PID: 14, Exe: "outlook.exe", SessionID: 1},
	}, t0)

	if len(ev) != 1 || ev[0].Payload["app"] != "outlook.exe" {
		t.Fatalf("solo Outlook debia reportarse, se obtuvo %v", ev)
	}
}

// El tope evita que un arranque masivo inunde la cola, y lo descartado tiene que
// quedar contado: un recorte silencioso se leeria como "no habia mas".
func TestTopePorSondeo(t *testing.T) {
	m := nuevaMaquinaApps()

	var procesos []proceso
	for i := range MaxAppsPorSondeo + 7 {
		procesos = append(procesos, proceso{PID: uint32(i), Exe: fmt.Sprintf("app%d.exe", i), SessionID: 1})
	}

	ev, descartados := m.observar(procesos, t0)
	if len(ev) != MaxAppsPorSondeo {
		t.Fatalf("se esperaban %d eventos, se obtuvieron %d", MaxAppsPorSondeo, len(ev))
	}
	if descartados != 7 {
		t.Fatalf("se esperaban 7 descartes, se contaron %d", descartados)
	}

	// Lo descartado no puede reaparecer en el siguiente sondeo: si reapareciera,
	// el tope solo aplazaria la avalancha en vez de contenerla.
	if ev, _ := m.observar(procesos, t0); len(ev) != 0 {
		t.Fatalf("el sondeo siguiente reintento %d apps descartadas", len(ev))
	}
}

func TestConocidoEvitaResolverRutas(t *testing.T) {
	m := nuevaMaquinaApps()

	if m.conocido(1, "chrome.exe") {
		t.Fatal("una app nunca vista no puede estar marcada como conocida")
	}
	m.observar([]proceso{{PID: 10, Exe: "chrome.exe", SessionID: 1}}, t0)

	// Insensible a mayusculas: Windows reporta el nombre como este en disco.
	if !m.conocido(1, "CHROME.EXE") {
		t.Error("deberia reconocerse sin importar mayusculas")
	}
	if m.conocido(2, "chrome.exe") {
		t.Error("otra sesion no comparte el estado")
	}
}

func TestCategoria(t *testing.T) {
	casos := map[string]string{
		"chrome.exe":   "navegador",
		"CHROME.EXE":   "navegador",
		"EXCEL.EXE":    "ofimatica",
		"anydesk.exe":  "acceso_remoto",
		"winscp.exe":   "transferencia",
		"raro-xyz.exe": "sin clasificar",
		"":             "sin clasificar",
	}
	for exe, esperada := range casos {
		if got := Categoria(exe); got != esperada {
			t.Errorf("Categoria(%q) = %q, se esperaba %q", exe, got, esperada)
		}
	}
}
