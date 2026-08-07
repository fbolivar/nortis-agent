//go:build windows

package clipwatch

import "testing"

// Lista de fuentes protegidas VACIA significa "el modo aplica a todo", no "no
// aplica a nada". Invertirlo dejaria el modo bloquear sin efecto en cuanto
// alguien guardara un perfil a medio configurar, y el panel diria que el canal
// esta cubierto.
func TestSinFuentesProtegidasElModoAplicaATodo(t *testing.T) {
	op := Opciones{Modo: "block"}

	for _, app := range []string{"excel.exe", "chrome.exe", "cualquiera.exe"} {
		if !op.debeVaciar(app) {
			t.Errorf("con lista vacia deberia vaciarse para %s", app)
		}
	}
}

func TestSoloSeVaciaDesdeLasFuentesProtegidas(t *testing.T) {
	op := Opciones{Modo: "block", FuentesProtegidas: []string{"sap.exe", "nomina.exe"}}

	if !op.debeVaciar("SAP.exe") {
		t.Error("la comparacion debe ignorar mayusculas")
	}
	if op.debeVaciar("chrome.exe") {
		t.Error("no debe vaciarse desde una aplicacion no protegida")
	}
}

// En allow y alert NO se toca el portapapeles del usuario. `alert` existe
// precisamente para medir antes de bloquear: si vaciara, no habria forma de
// evaluar el impacto sin sufrirlo.
func TestEnAllowYAlertNoSeVacia(t *testing.T) {
	for _, modo := range []string{"allow", "alert", ""} {
		op := Opciones{Modo: modo}
		if op.debeVaciar("sap.exe") {
			t.Errorf("el modo %q no puede vaciar el portapapeles", modo)
		}
	}
}
