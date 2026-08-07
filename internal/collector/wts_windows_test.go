//go:build windows

package collector

import (
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// TestEnumerarSesionesDevuelveValoresPlausibles comprueba contra el sistema real
// que los campos se leen donde toca.
//
// Es la unica parte que las pruebas de la maquina de estados no pueden cubrir: un
// desplazamiento mal calculado en WTSINFOW no da error, devuelve basura. Y basura
// aqui significa reportar un equipo como inactivo desde 1601, o una sesion
// iniciada dentro de veinte años. No se afirman valores exactos —dependen de la
// maquina— sino que caigan en rangos donde solo entra un dato correcto.
func TestEnumerarSesionesDevuelveValoresPlausibles(t *testing.T) {
	sesiones, err := enumerarSesiones()
	if err != nil {
		t.Fatalf("enumerarSesiones: %v", err)
	}
	if len(sesiones) == 0 {
		// Pasa en los runners de CI, que no tienen sesion interactiva.
		t.Skip("sin sesiones interactivas en este equipo")
	}

	ahora := time.Now()
	for _, s := range sesiones {
		if s.ID == 0 {
			t.Error("la sesion 0 es la de los servicios y nunca debe reportarse")
		}
		if s.Usuario == "" {
			t.Error("se reporto una sesion sin usuario")
		}
		if s.Inactivo < 0 || s.Inactivo > 30*24*time.Hour {
			t.Errorf("inactividad implausible (%v): revisar la resta de FILETIMEs", s.Inactivo)
		}

		// SessionFlags es de donde sale la presencia en las sesiones de consola.
		// Un valor distinto de bloqueada/desbloqueada significa que el campo se
		// leyo del sitio equivocado, y entonces todo equipo pareceria bloqueado o
		// ninguno lo pareceria — sin dar error en ningun momento.
		info, ok := consultarInfo(s.ID)
		if !ok {
			t.Errorf("no se pudo consultar la informacion extendida de la sesion %d", s.ID)
		} else if info.SessionFlags != wtsSessionStateLock && info.SessionFlags != wtsSessionStateUnlock {
			t.Errorf("SessionFlags con valor inesperado (%d): el desplazamiento del campo esta mal", info.SessionFlags)
		}
		if s.LogonTime.IsZero() {
			continue
		}
		if s.LogonTime.After(ahora) {
			t.Errorf("sesion iniciada en el futuro (%v): el origen del FILETIME esta mal", s.LogonTime)
		}
		if ahora.Sub(s.LogonTime) > 365*24*time.Hour {
			t.Errorf("sesion iniciada hace mas de un año (%v): epoca equivocada", s.LogonTime)
		}
		t.Logf("sesion %d usuario=%q inactivo=%v inicio=%v", s.ID, s.Usuario, s.Inactivo.Round(time.Second), s.LogonTime)
	}
}

// TestEnumerarProcesosDevuelveLaSesionInteractiva comprueba que la asociacion
// proceso -> sesion funciona: sin ella, todos los procesos caerian en la sesion 0
// y no se reportaria ni una sola aplicacion.
func TestEnumerarProcesosDevuelveLaSesionInteractiva(t *testing.T) {
	c := NewAppsCollector(zerolog.Nop())

	procesos, err := c.enumerar()
	if err != nil {
		t.Fatalf("enumerar: %v", err)
	}
	if len(procesos) == 0 {
		t.Skip("sin procesos en sesiones interactivas")
	}

	conRuta := 0
	for _, p := range procesos {
		if p.SessionID == 0 {
			t.Errorf("proceso %q reportado en la sesion 0", p.Exe)
		}
		if p.Exe == "" {
			t.Error("proceso sin nombre de ejecutable")
		}
		if p.Ruta != "" {
			conRuta++
		}
	}

	// Que alguna ruta se resuelva prueba que OpenProcess +
	// QueryFullProcessImageName funcionan con el permiso minimo que se pide. Que
	// fallen todas seria un permiso mal elegido, no mala suerte.
	if conRuta == 0 {
		t.Error("no se resolvio la ruta de ningun ejecutable")
	}
	t.Logf("%d procesos en sesiones interactivas, %d con ruta resuelta", len(procesos), conRuta)
}
