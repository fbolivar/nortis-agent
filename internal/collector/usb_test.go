package collector

import (
	"testing"
	"time"
)

func ahora() time.Time { return time.Date(2026, 8, 7, 16, 0, 0, 0, time.UTC) }

func TestUSBEmiteSoloAlConectar(t *testing.T) {
	m := nuevaMaquinaUSB()
	memoria := volumen{Letra: "E:", Serial: "AA11BB22", Etiqueta: "KINGSTON"}

	if ev := m.observar([]volumen{memoria}, "allow", ahora()); len(ev) != 1 {
		t.Fatalf("la primera conexion deberia emitir 1 evento, emitio %d", len(ev))
	}

	// Sigue conectada: no puede volver a emitir. Sin esto, una memoria olvidada
	// en el puerto generaria un incidente critico cada tres segundos.
	for i := 0; i < 5; i++ {
		if ev := m.observar([]volumen{memoria}, "allow", ahora()); len(ev) != 0 {
			t.Fatalf("una memoria que sigue puesta no debe emitir; emitio %d", len(ev))
		}
	}
}

func TestUSBReconectarVuelveAEmitir(t *testing.T) {
	m := nuevaMaquinaUSB()
	memoria := volumen{Letra: "E:", Serial: "AA11BB22"}

	m.observar([]volumen{memoria}, "allow", ahora())
	m.observar(nil, "allow", ahora()) // se retira

	// Entrar y salir tres veces en una tarde son tres oportunidades de sacar
	// informacion, no una.
	if ev := m.observar([]volumen{memoria}, "allow", ahora()); len(ev) != 1 {
		t.Fatalf("reconectar deberia emitir de nuevo, emitio %d", len(ev))
	}
}

// Windows reasigna letras de unidad. Si la identidad dependiera de la letra, la
// misma memoria en otro puerto pasaria por un dispositivo distinto y duplicaria
// el incidente.
func TestUSBLaLetraNoCambiaLaIdentidad(t *testing.T) {
	m := nuevaMaquinaUSB()

	m.observar([]volumen{{Letra: "E:", Serial: "AA11BB22"}}, "allow", ahora())

	ev := m.observar([]volumen{{Letra: "G:", Serial: "AA11BB22"}}, "allow", ahora())
	if len(ev) != 0 {
		t.Fatalf("la misma memoria en otra letra no es un dispositivo nuevo; emitio %d", len(ev))
	}
}

// El serial de volumen se lo lleva un formateo, asi que una lista blanca
// construida sobre el se sortea formateando la memoria. Cuando toca usarlo, el
// evento tiene que decir que es un identificador debil.
func TestUSBSerialDeVolumenSeMarcaComoDebil(t *testing.T) {
	v := volumen{Letra: "E:", SerialVolumen: "1A2B3C4D"}

	if got := v.SerialEfectivo(); got != "vol:1A2B3C4D" {
		t.Fatalf("se esperaba el respaldo marcado, se obtuvo %q", got)
	}

	// Con serial de dispositivo presente, ese manda.
	v.Serial = "AA11BB22"
	if got := v.SerialEfectivo(); got != "AA11BB22" {
		t.Fatalf("el serial de dispositivo debe tener prioridad, se obtuvo %q", got)
	}
}

func TestUSBPayloadLlevaLoQueElMotorDLPNecesita(t *testing.T) {
	m := nuevaMaquinaUSB()

	ev := m.observar([]volumen{{
		Letra: "E:", Serial: "AA11BB22", Etiqueta: "KINGSTON",
		CapacidadByte: 64_000_000_000, Usuario: "jperez",
	}}, "block", ahora())

	if len(ev) != 1 {
		t.Fatalf("se esperaba 1 evento, hubo %d", len(ev))
	}

	p := ev[0].Payload
	// La regla usb.dispositivo_no_autorizado compara contra `serial` y cae a
	// `label`. Si faltaran, el incidente se abriria sin poder decir que memoria
	// fue.
	if p["serial"] != "AA11BB22" {
		t.Errorf("serial: %v", p["serial"])
	}
	if p["label"] != "KINGSTON" {
		t.Errorf("label: %v", p["label"])
	}
	if p["enforcement"] != "block" {
		t.Errorf("enforcement: %v", p["enforcement"])
	}
	if p["user"] != "jperez" {
		t.Errorf("user: %v", p["user"])
	}

	// Y NUNCA contenido: el payload solo describe el dispositivo.
	for _, prohibido := range []string{"content", "files", "data"} {
		if _, hay := p[prohibido]; hay {
			t.Errorf("el payload no puede llevar %q", prohibido)
		}
	}
}
