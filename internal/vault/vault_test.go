package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// prepararOrigen crea una carpeta con archivos, uno de ellos de varios bloques.
func prepararOrigen(t *testing.T) (string, map[string][]byte) {
	t.Helper()
	dir := t.TempDir()
	archivos := map[string][]byte{
		"nota.txt":        []byte("datos personales: cedula 1020304050"),
		"sub/informe.csv": bytes.Repeat([]byte("a,b,c\n"), 100),
		"sub/grande.bin":  bytes.Repeat([]byte("NORTIS-"), 40_000), // ~280 KiB: varios bloques
		"vacio.dat":       {},
	}
	for nombre, contenido := range archivos {
		ruta := filepath.Join(dir, filepath.FromSlash(nombre))
		if err := os.MkdirAll(filepath.Dir(ruta), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(ruta, contenido, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir, archivos
}

func TestSellarAbrirRoundTrip(t *testing.T) {
	origen, archivos := prepararOrigen(t)
	cont := filepath.Join(t.TempDir(), "caja.nrtv")
	dest := t.TempDir()

	if err := Sellar(origen, cont, "contrasena-larga"); err != nil {
		t.Fatalf("Sellar: %v", err)
	}
	if err := Abrir(cont, dest, "contrasena-larga"); err != nil {
		t.Fatalf("Abrir: %v", err)
	}
	for nombre, esperado := range archivos {
		got, err := os.ReadFile(filepath.Join(dest, filepath.FromSlash(nombre)))
		if err != nil {
			t.Fatalf("no se extrajo %s: %v", nombre, err)
		}
		if !bytes.Equal(got, esperado) {
			t.Fatalf("%s difiere: %d vs %d bytes", nombre, len(got), len(esperado))
		}
	}
}

func TestContrasenaIncorrecta(t *testing.T) {
	origen, _ := prepararOrigen(t)
	cont := filepath.Join(t.TempDir(), "caja.nrtv")
	if err := Sellar(origen, cont, "la-buena"); err != nil {
		t.Fatal(err)
	}
	err := Abrir(cont, t.TempDir(), "la-mala")
	if !errors.Is(err, ErrPassword) {
		t.Fatalf("se esperaba ErrPassword, se obtuvo: %v", err)
	}
}

func TestTruncamientoFalla(t *testing.T) {
	origen, _ := prepararOrigen(t)
	cont := filepath.Join(t.TempDir(), "caja.nrtv")
	if err := Sellar(origen, cont, "contrasena-larga"); err != nil {
		t.Fatal(err)
	}
	// Se recorta el ultimo bloque: la autenticacion (bit de "ultimo" en el AAD)
	// debe detectar que el contenedor esta incompleto.
	info, err := os.Stat(cont)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(cont, info.Size()-200); err != nil {
		t.Fatal(err)
	}
	if err := Abrir(cont, t.TempDir(), "contrasena-larga"); err == nil {
		t.Fatal("un contenedor truncado no deberia abrirse sin error")
	}
}

func TestManipulacionFalla(t *testing.T) {
	origen, _ := prepararOrigen(t)
	cont := filepath.Join(t.TempDir(), "caja.nrtv")
	if err := Sellar(origen, cont, "contrasena-larga"); err != nil {
		t.Fatal(err)
	}
	datos, err := os.ReadFile(cont)
	if err != nil {
		t.Fatal(err)
	}
	// Se voltea un byte del cuerpo cifrado: GCM debe rechazarlo.
	datos[len(datos)-50] ^= 0xff
	if err := os.WriteFile(cont, datos, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Abrir(cont, t.TempDir(), "contrasena-larga"); !errors.Is(err, ErrPassword) {
		t.Fatalf("se esperaba fallo de autenticacion, se obtuvo: %v", err)
	}
}
