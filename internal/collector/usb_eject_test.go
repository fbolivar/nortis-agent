//go:build windows

package collector

import "testing"

// Un dispositivo SIN serial no puede estar autorizado nunca.
//
// Si se permitiera, bastaria con conseguir una memoria que no exponga su serial
// —hay adaptadores baratos que no lo hacen— para saltarse la lista blanca
// entera. Es el agujero mas obvio de este control y tiene que estar cerrado.
func TestSinSerialNuncaEstaAutorizado(t *testing.T) {
	lista := []string{"KINGSTON-AF31C", "SANDISK-9920"}

	for _, vacio := range []string{"", "   "} {
		if AutorizadoEnListaBlanca(vacio, lista) {
			t.Errorf("un dispositivo sin serial (%q) no puede autorizarse", vacio)
		}
	}
}

// El serial se transcribe a mano desde una etiqueta o desde el panel: exigir
// coincidencia exacta haria que una lista blanca correcta fallara por un espacio
// al final, y el administrador no tendria forma de verlo.
func TestLaComparacionToleraMayusculasYEspacios(t *testing.T) {
	lista := []string{" kingston-af31c "}

	for _, s := range []string{"KINGSTON-AF31C", "kingston-af31c", "  KINGSTON-AF31C  "} {
		if !AutorizadoEnListaBlanca(s, lista) {
			t.Errorf("%q deberia estar autorizado", s)
		}
	}
}

func TestUnSerialAjenoNoPasa(t *testing.T) {
	lista := []string{"KINGSTON-AF31C"}

	for _, s := range []string{"KINGSTON-AF31D", "SANDISK-9920", "vol:1A2B3C4D"} {
		if AutorizadoEnListaBlanca(s, lista) {
			t.Errorf("%q NO deberia estar autorizado", s)
		}
	}
}

// Con lista blanca vacia no se autoriza a nadie por esta via: el modo `block`
// sin lista se resuelve deshabilitando el driver, no expulsando.
func TestListaVaciaNoAutorizaNada(t *testing.T) {
	if AutorizadoEnListaBlanca("KINGSTON-AF31C", nil) {
		t.Error("una lista blanca vacia no puede autorizar dispositivos")
	}
}
