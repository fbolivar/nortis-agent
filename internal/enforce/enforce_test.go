package enforce

import (
	"strings"
	"testing"
)

// El archivo hosts del cliente puede contener la resolucion de su intranet.
// Pisarla dejaria a la empresa sin acceso a sus propios sistemas, y un agente de
// seguridad que tumba la red interna se desinstala esa misma tarde.
func TestNoSeTocaLoQueNoEsNuestro(t *testing.T) {
	original := "127.0.0.1 localhost\r\n10.0.0.5 erp.interno\r\n10.0.0.6 nomina.interno\r\n"

	conBloqueo := ComponerHosts(original, []string{"wetransfer.com"})

	for _, linea := range []string{"127.0.0.1 localhost", "10.0.0.5 erp.interno", "10.0.0.6 nomina.interno"} {
		if !strings.Contains(conBloqueo, linea) {
			t.Errorf("se perdio una entrada del cliente: %s", linea)
		}
	}
	if !strings.Contains(conBloqueo, "0.0.0.0 wetransfer.com") {
		t.Error("no se aplico el bloqueo")
	}

	// Y al revertir, el archivo tiene que quedar exactamente como estaba.
	revertido := QuitarBloqueNortis(conBloqueo)
	for _, linea := range []string{"10.0.0.5 erp.interno", "10.0.0.6 nomina.interno"} {
		if !strings.Contains(revertido, linea) {
			t.Errorf("la reversion se llevo una entrada del cliente: %s", linea)
		}
	}
	if strings.Contains(revertido, "wetransfer.com") {
		t.Error("la reversion dejo entradas de Nortis")
	}
}

// Aplicar dos veces no puede duplicar el bloque: el archivo hosts creceria sin
// limite y el antivirus del cliente ve con muy malos ojos que algo reescriba ese
// archivo una y otra vez.
func TestAplicarDosVecesEsIdempotente(t *testing.T) {
	base := "127.0.0.1 localhost\r\n"

	una := ComponerHosts(base, []string{"wetransfer.com", "dropbox.com"})
	dos := ComponerHosts(una, []string{"wetransfer.com", "dropbox.com"})

	if una != dos {
		t.Fatal("aplicar la misma politica dos veces produjo un archivo distinto")
	}
	if strings.Count(dos, MarcaInicio) != 1 {
		t.Fatalf("el bloque aparece %d veces", strings.Count(dos, MarcaInicio))
	}
}

// Quien escribe "wetransfer.com" y quien escribe "www.wetransfer.com" tienen la
// misma intencion; dejar una de las dos abierta hace inutil la otra.
func TestSeBloqueaTambienLaVarianteWWW(t *testing.T) {
	out := ComponerHosts("", []string{"wetransfer.com"})

	if !strings.Contains(out, "0.0.0.0 wetransfer.com") {
		t.Error("falta el dominio")
	}
	if !strings.Contains(out, "0.0.0.0 www.wetransfer.com") {
		t.Error("falta la variante www")
	}

	// Pero no se duplica el www cuando el dominio ya lo trae.
	out2 := ComponerHosts("", []string{"www.dropbox.com"})
	if strings.Contains(out2, "www.www.dropbox.com") {
		t.Error("se duplico el prefijo www")
	}
}

// Si un editor o un apagon dejaron el archivo a medias, hay que limpiar igual en
// vez de dejar entradas huerfanas que nadie sabria de donde salieron.
func TestBloqueSinMarcaDeCierreSeLimpia(t *testing.T) {
	roto := "127.0.0.1 localhost\r\n" + MarcaInicio + "\r\n0.0.0.0 wetransfer.com\r\n"

	limpio := QuitarBloqueNortis(roto)

	if strings.Contains(limpio, "wetransfer.com") {
		t.Error("quedaron entradas huerfanas de Nortis")
	}
	if !strings.Contains(limpio, "127.0.0.1 localhost") {
		t.Error("se perdio la entrada del cliente")
	}
}

func TestWebmailSoloSeBloqueaSiLaPoliticaLoPide(t *testing.T) {
	sin, _ := DominiosABloquear([]string{"wetransfer.com"}, nil, false)
	if len(sin) != 1 {
		t.Fatalf("sin block_webmail solo deberia haber 1 dominio, hay %d", len(sin))
	}

	con, _ := DominiosABloquear([]string{"wetransfer.com"}, nil, true)
	if len(con) <= 1 {
		t.Fatal("con block_webmail deberian añadirse los proveedores conocidos")
	}

	var hayGmail bool
	for _, d := range con {
		if d == "mail.google.com" {
			hayGmail = true
		}
	}
	if !hayGmail {
		t.Error("falta mail.google.com en el bloqueo de webmail")
	}
}

// La lista blanca —"permitir solo estos y bloquear el resto"— es imposible con
// el archivo hosts, que solo sabe nombrar lo que se bloquea. Tiene que
// informarse en vez de fingir que esta cubierto: un panel que muestra un equipo
// protegido cuando no lo esta es peor que uno que admite el hueco.
func TestLaListaBlancaSeReportaComoNoAplicable(t *testing.T) {
	_, soloAlerta := DominiosABloquear(nil, []string{"empresa.com"}, false)

	if len(soloAlerta) == 0 {
		t.Fatal("la lista blanca debe reportarse como no aplicable, no ignorarse en silencio")
	}
	if !strings.Contains(strings.ToLower(soloAlerta[0]), "lista blanca") {
		t.Errorf("el aviso deberia nombrar el control: %q", soloAlerta[0])
	}
}

func TestSinDominiosNoSeEscribeBloque(t *testing.T) {
	base := "127.0.0.1 localhost\r\n"
	out := ComponerHosts(base, nil)

	if strings.Contains(out, MarcaInicio) {
		t.Error("sin dominios que bloquear no debe escribirse el bloque")
	}
	if !strings.Contains(out, "127.0.0.1 localhost") {
		t.Error("se perdio el contenido original")
	}
}

func TestDominiosSeNormalizanYNoSeRepiten(t *testing.T) {
	out, _ := DominiosABloquear(
		[]string{"WeTransfer.com", "  wetransfer.com  ", "dropbox.com", ""},
		nil, false,
	)

	if len(out) != 2 {
		t.Fatalf("se esperaban 2 dominios unicos, hay %d: %v", len(out), out)
	}
	for _, d := range out {
		if d != strings.ToLower(strings.TrimSpace(d)) {
			t.Errorf("dominio sin normalizar: %q", d)
		}
	}
}
