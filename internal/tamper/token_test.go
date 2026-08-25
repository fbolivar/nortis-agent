package tamper

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

// par genera un par de claves de prueba. Las pruebas no usan la clave fijada en
// el binario: firman con la suya y verifican con su propia publica, de modo que
// la criptografia se valida sin depender de ninguna ceremonia de claves.
func par(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("no se pudo generar el par de claves: %v", err)
	}
	return pub, priv
}

func valeValido(endpointID string, ahora time.Time) Vale {
	return Vale{
		Motivo:     MotivoDesinstalar,
		EndpointID: endpointID,
		EmitidoEn:  ahora,
		CaducaEn:   ahora.Add(30 * time.Minute),
		Nonce:      "n-1",
	}
}

func TestVerificarValeCorrecto(t *testing.T) {
	pub, priv := par(t)
	ahora := time.Now().UTC()

	token, err := Firmar(valeValido("ep-123", ahora), priv)
	if err != nil {
		t.Fatalf("Firmar: %v", err)
	}

	v, err := VerificarCon(pub, token, "ep-123", ahora)
	if err != nil {
		t.Fatalf("un vale correcto no debia fallar: %v", err)
	}
	if v.EndpointID != "ep-123" {
		t.Fatalf("endpoint devuelto inesperado: %q", v.EndpointID)
	}
}

func TestRechazaFirmaDeOtraClave(t *testing.T) {
	_, priv := par(t)    // se firma con esta
	otraPub, _ := par(t) // se verifica con otra distinta
	ahora := time.Now().UTC()

	token, _ := Firmar(valeValido("ep-123", ahora), priv)

	if _, err := VerificarCon(otraPub, token, "ep-123", ahora); !errors.Is(err, ErrFirmaInvalida) {
		t.Fatalf("una firma de otra clave debia dar ErrFirmaInvalida, dio: %v", err)
	}
}

func TestRechazaValeDeOtroEquipo(t *testing.T) {
	pub, priv := par(t)
	ahora := time.Now().UTC()

	// El vale se emite para ep-AAA pero lo presenta ep-BBB: es el ataque de
	// robar el vale de un equipo para desinstalar otro.
	token, _ := Firmar(valeValido("ep-AAA", ahora), priv)

	if _, err := VerificarCon(pub, token, "ep-BBB", ahora); !errors.Is(err, ErrValeOtroEquipo) {
		t.Fatalf("un vale de otro equipo debia dar ErrValeOtroEquipo, dio: %v", err)
	}
}

func TestRechazaValeCaducado(t *testing.T) {
	pub, priv := par(t)
	emitido := time.Now().UTC().Add(-2 * time.Hour)

	vale := valeValido("ep-123", emitido)
	vale.CaducaEn = emitido.Add(30 * time.Minute) // caduco hace ~90 min
	token, _ := Firmar(vale, priv)

	if _, err := VerificarCon(pub, token, "ep-123", time.Now().UTC()); !errors.Is(err, ErrValeCaducado) {
		t.Fatalf("un vale caducado debia dar ErrValeCaducado, dio: %v", err)
	}
}

func TestRechazaMotivoDistinto(t *testing.T) {
	pub, priv := par(t)
	ahora := time.Now().UTC()

	vale := valeValido("ep-123", ahora)
	vale.Motivo = "otra-cosa"
	token, _ := Firmar(vale, priv)

	if _, err := VerificarCon(pub, token, "ep-123", ahora); !errors.Is(err, ErrMotivoInesperado) {
		t.Fatalf("un motivo distinto debia dar ErrMotivoInesperado, dio: %v", err)
	}
}

func TestRechazaCuerpoManipulado(t *testing.T) {
	pub, priv := par(t)
	ahora := time.Now().UTC()
	token, _ := Firmar(valeValido("ep-123", ahora), priv)

	// Se altera un caracter del cuerpo: la firma deja de cuadrar.
	b := []byte(token)
	if b[0] == 'A' {
		b[0] = 'B'
	} else {
		b[0] = 'A'
	}

	if _, err := VerificarCon(pub, string(b), "ep-123", ahora); err == nil {
		t.Fatal("un cuerpo manipulado no debia verificar")
	}
}

func TestRechazaTokenMalFormado(t *testing.T) {
	pub, _ := par(t)
	for _, malo := range []string{"", "sinpunto", ".", "a.", ".b", "a.b.c"} {
		if _, err := VerificarCon(pub, malo, "ep-123", time.Now().UTC()); err == nil {
			t.Fatalf("el token %q debia rechazarse", malo)
		}
	}
}
