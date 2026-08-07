package collector

import (
	"testing"
	"time"

	"github.com/fbolivar/nortis-agent/internal/contract"
)

var t0 = time.Date(2026, 8, 7, 9, 0, 0, 0, time.UTC)

// tipos extrae los tipos de una lista de eventos, que es lo que se afirma en
// casi todas las pruebas.
func tipos(eventos []contract.Event) []contract.EventType {
	out := make([]contract.EventType, 0, len(eventos))
	for _, e := range eventos {
		out = append(out, e.Type)
	}
	return out
}

func iguales(a []contract.EventType, b ...contract.EventType) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestSesionNuevaEmiteLogon(t *testing.T) {
	m := nuevaMaquinaSesiones()

	ev := m.observar([]sesion{{ID: 1, Usuario: "ana", Estado: wtsActive}}, t0)

	if !iguales(tipos(ev), contract.EventLogon) {
		t.Fatalf("se esperaba un logon, se obtuvo %v", tipos(ev))
	}
	if ev[0].Payload["user"] != "ana" {
		t.Errorf("usuario incorrecto: %v", ev[0].Payload["user"])
	}
	if ev[0].Payload["session_type"] != "console" {
		t.Errorf("tipo de sesion incorrecto: %v", ev[0].Payload["session_type"])
	}
}

// El caso que mas importa: una sesion estable no puede generar nada. Si genera,
// cada sondeo mete un evento y la cola se llena sola.
func TestSesionEstableNoEmiteNada(t *testing.T) {
	m := nuevaMaquinaSesiones()
	s := []sesion{{ID: 1, Usuario: "ana", Estado: wtsActive}}
	m.observar(s, t0)

	for i := 1; i <= 5; i++ {
		if ev := m.observar(s, t0.Add(time.Duration(i)*time.Minute)); len(ev) != 0 {
			t.Fatalf("sondeo %d genero eventos: %v", i, tipos(ev))
		}
	}
}

func TestInactividadSoloEnLaTransicion(t *testing.T) {
	m := nuevaMaquinaSesiones()
	m.observar([]sesion{{ID: 1, Usuario: "ana", Estado: wtsActive}}, t0)

	// Justo por debajo del umbral: todavia no es inactividad.
	if ev := m.observar([]sesion{{ID: 1, Usuario: "ana", Inactivo: UmbralInactividad - time.Second}}, t0); len(ev) != 0 {
		t.Fatalf("se emitio inactividad antes del umbral: %v", tipos(ev))
	}

	ev := m.observar([]sesion{{ID: 1, Usuario: "ana", Inactivo: UmbralInactividad}}, t0)
	if !iguales(tipos(ev), contract.EventIdleStart) {
		t.Fatalf("se esperaba idle_start, se obtuvo %v", tipos(ev))
	}
	if ev[0].Payload["idle_seconds"] != int(UmbralInactividad.Seconds()) {
		t.Errorf("idle_seconds incorrecto: %v", ev[0].Payload["idle_seconds"])
	}

	// Sigue inactiva: no se repite. Aqui esta el error que generaria miles de
	// eventos en una noche.
	if ev := m.observar([]sesion{{ID: 1, Usuario: "ana", Inactivo: 3 * time.Hour}}, t0); len(ev) != 0 {
		t.Fatalf("se repitio idle_start: %v", tipos(ev))
	}

	if ev := m.observar([]sesion{{ID: 1, Usuario: "ana", Inactivo: 0}}, t0); !iguales(tipos(ev), contract.EventIdleEnd) {
		t.Fatalf("se esperaba idle_end, se obtuvo %v", tipos(ev))
	}
}

func TestSesionQueDesapareceEmiteLogoff(t *testing.T) {
	m := nuevaMaquinaSesiones()
	m.observar([]sesion{{ID: 1, Usuario: "ana", Estado: wtsActive}}, t0)

	ev := m.observar(nil, t0.Add(time.Minute))
	if !iguales(tipos(ev), contract.EventLogoff) {
		t.Fatalf("se esperaba logoff, se obtuvo %v", tipos(ev))
	}
	if ev[0].Payload["user"] != "ana" {
		t.Errorf("el logoff debe llevar el usuario que se fue, no %v", ev[0].Payload["user"])
	}

	// Y no se repite: si no se olvidara, cada sondeo posterior emitiria otro.
	if ev := m.observar(nil, t0.Add(2*time.Minute)); len(ev) != 0 {
		t.Fatalf("logoff repetido: %v", tipos(ev))
	}
}

// Cambio rapido de usuario: mismo identificador de sesion, persona distinta. Sin
// el logoff, el panel atribuiria a la nueva la actividad de la anterior.
func TestCambioDeUsuarioEmiteLogoffYLogon(t *testing.T) {
	m := nuevaMaquinaSesiones()
	m.observar([]sesion{{ID: 2, Usuario: "ana", Estado: wtsActive}}, t0)

	ev := m.observar([]sesion{{ID: 2, Usuario: "beto", Estado: wtsActive}}, t0)
	if !iguales(tipos(ev), contract.EventLogoff, contract.EventLogon) {
		t.Fatalf("se esperaba logoff+logon, se obtuvo %v", tipos(ev))
	}
	if ev[0].Payload["user"] != "ana" || ev[1].Payload["user"] != "beto" {
		t.Errorf("usuarios incorrectos: %v / %v", ev[0].Payload["user"], ev[1].Payload["user"])
	}
}

func TestSesionDesconectadaSeReportaComoRemota(t *testing.T) {
	m := nuevaMaquinaSesiones()

	ev := m.observar([]sesion{{ID: 3, Usuario: "ana", Estado: wtsDisconnected}}, t0)
	if ev[0].Payload["session_type"] != "remote" {
		t.Errorf("se esperaba remote, se obtuvo %v", ev[0].Payload["session_type"])
	}
	if tipoSesion(wtsConnected) != "console" {
		t.Errorf("wtsConnected deberia ser console")
	}
}

// Varias sesiones a la vez (un equipo con escritorio remoto): cada una lleva su
// propio estado y no se pisan.
func TestSesionesIndependientes(t *testing.T) {
	m := nuevaMaquinaSesiones()
	m.observar([]sesion{
		{ID: 1, Usuario: "ana", Estado: wtsActive},
		{ID: 2, Usuario: "beto", Estado: wtsActive},
	}, t0)

	ev := m.observar([]sesion{
		{ID: 1, Usuario: "ana", Estado: wtsActive, Inactivo: time.Hour},
		{ID: 2, Usuario: "beto", Estado: wtsActive},
	}, t0)

	if !iguales(tipos(ev), contract.EventIdleStart) {
		t.Fatalf("solo la sesion 1 debia entrar en inactividad, se obtuvo %v", tipos(ev))
	}
	if ev[0].Payload["user"] != "ana" {
		t.Errorf("la inactividad se atribuyo a %v", ev[0].Payload["user"])
	}
}
