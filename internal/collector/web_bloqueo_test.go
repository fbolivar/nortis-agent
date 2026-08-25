package collector

import (
	"testing"

	"github.com/fbolivar/nortis-agent/internal/contract"
)

func TestDominioBloqueado(t *testing.T) {
	p := &contract.Policy{}
	p.Web.BlockedDomains = []string{"eltiempo.com"}
	p.Web.BlockWebmail = true

	casos := []struct {
		dominio string
		quiero  bool
	}{
		{"eltiempo.com", true},
		{"www.eltiempo.com", true},      // sufijo
		{"noeltiempo.com", false},       // no es sufijo de dominio
		{"deportes.eltiempo.com", true}, // subdominio
		{"gmail.com", true},             // webmail
		{"mail.google.com", true},       // webmail
		{"www.gob.co", false},           // ni bloqueado ni webmail
	}
	for _, c := range casos {
		got, _ := DominioBloqueado(c.dominio, p)
		if got != c.quiero {
			t.Errorf("DominioBloqueado(%q)=%v; quiero %v", c.dominio, got, c.quiero)
		}
	}
}

func TestListaBlancaBloqueaLoDemas(t *testing.T) {
	p := &contract.Policy{}
	p.Web.AllowedDomains = []string{"gob.co", "empresa.com"}

	if b, _ := DominioBloqueado("intranet.empresa.com", p); b {
		t.Fatal("un dominio de la lista blanca no debe bloquearse")
	}
	if b, _ := DominioBloqueado("facebook.com", p); !b {
		t.Fatal("con lista blanca, lo que no esta en ella debe bloquearse")
	}
}

func TestSinPoliticaNoBloquea(t *testing.T) {
	if b, _ := DominioBloqueado("cualquiera.com", nil); b {
		t.Fatal("sin politica no se bloquea nada")
	}
}
