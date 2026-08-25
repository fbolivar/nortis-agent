package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/rs/zerolog"
)

func TestEsMasNueva(t *testing.T) {
	casos := []struct {
		candidata, actual string
		quiero            bool
	}{
		{"1.0.0", "0.0.0", true},
		{"1.2.0", "1.1.9", true},
		{"1.0.1", "1.0.0", true},
		{"1.0.0", "1.0.0", false},
		{"1.0.0", "1.0.1", false},
		{"0.9.9", "1.0.0", false},
		{"1.0.0", "0.0.0-dev", true}, // cualquier version publicada supera a la de desarrollo
		{"1.2.3-rc1", "1.2.2", true}, // el sufijo se ignora
	}
	for _, c := range casos {
		if got := EsMasNueva(c.candidata, c.actual); got != c.quiero {
			t.Errorf("EsMasNueva(%q,%q)=%v; quiero %v", c.candidata, c.actual, got, c.quiero)
		}
	}
}

func servidorConCuerpo(cuerpo []byte) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(cuerpo)
	}))
}

func sha256hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func TestDescargaAceptaHashCorrecto(t *testing.T) {
	cuerpo := []byte("contenido de un MSI de prueba")
	srv := servidorConCuerpo(cuerpo)
	defer srv.Close()

	u := New(nil, "0.0.0", srv.Client(), zerolog.Nop())
	ruta, err := u.descargarYVerificar(context.Background(), srv.URL, sha256hex(cuerpo))
	if err != nil {
		t.Fatalf("un hash correcto no debia fallar: %v", err)
	}
	defer os.Remove(ruta)

	guardado, err := os.ReadFile(ruta)
	if err != nil {
		t.Fatalf("no se pudo leer el archivo descargado: %v", err)
	}
	if string(guardado) != string(cuerpo) {
		t.Fatal("el contenido descargado no coincide con el servido")
	}
}

func TestDescargaRechazaHashIncorrecto(t *testing.T) {
	srv := servidorConCuerpo([]byte("binario manipulado"))
	defer srv.Close()

	u := New(nil, "0.0.0", srv.Client(), zerolog.Nop())
	// Se pide un hash que NO corresponde al cuerpo servido: debe rechazarse.
	ruta, err := u.descargarYVerificar(context.Background(), srv.URL, sha256hex([]byte("lo que esperabamos")))
	if err == nil {
		os.Remove(ruta)
		t.Fatal("un hash que no coincide debia rechazarse")
	}
	if ruta != "" {
		t.Fatalf("no debia quedar archivo tras un hash invalido, quedo: %s", ruta)
	}
}
