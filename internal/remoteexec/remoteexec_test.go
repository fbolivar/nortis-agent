package remoteexec

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"
)

// La propiedad de seguridad central: el agente SOLO ejecuta tareas firmadas por
// la consola. Estos tests fijan que una firma valida se acepta y que cualquier
// alteracion —payload, endpoint, tipo o firma— se rechaza.
func TestVerificarFirma(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("no se pudo generar el par de claves: %v", err)
	}

	const (
		endpoint = "11111111-1111-1111-1111-111111111111"
		kind     = "install_msi"
		payload  = `{"url":"https://x/a.msi","sha256":"` +
			"0000000000000000000000000000000000000000000000000000000000000000" +
			`","args":"","not_after":9999999999}`
	)
	firma := base64.StdEncoding.EncodeToString(
		ed25519.Sign(priv, BytesCanonicos(endpoint, kind, payload)))

	// Caso valido.
	if err := VerificarFirma(pub, endpoint, kind, payload, firma); err != nil {
		t.Fatalf("una firma valida deberia aceptarse: %v", err)
	}

	// Payload alterado (el ataque de inyeccion en la base): misma firma, otro
	// contenido -> debe rechazarse.
	malo := `{"url":"https://x/EVIL.msi","sha256":"` +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		`","args":"","not_after":9999999999}`
	if err := VerificarFirma(pub, endpoint, kind, malo, firma); err == nil {
		t.Error("un payload alterado con firma vieja NO debe aceptarse")
	}

	// Endpoint distinto: una tarea firmada para A no vale en B.
	if err := VerificarFirma(pub, "22222222-2222-2222-2222-222222222222", kind, payload, firma); err == nil {
		t.Error("una tarea firmada para otro equipo NO debe aceptarse")
	}

	// Tipo distinto.
	if err := VerificarFirma(pub, endpoint, "restart", payload, firma); err == nil {
		t.Error("cambiar el tipo debe invalidar la firma")
	}

	// Firma corrupta.
	if err := VerificarFirma(pub, endpoint, kind, payload, "no-es-base64!!"); err == nil {
		t.Error("una firma que no es base64 debe rechazarse")
	}

	// Firma de otra clave (no la de la consola).
	_, otraPriv, _ := ed25519.GenerateKey(nil)
	otraFirma := base64.StdEncoding.EncodeToString(
		ed25519.Sign(otraPriv, BytesCanonicos(endpoint, kind, payload)))
	if err := VerificarFirma(pub, endpoint, kind, payload, otraFirma); err == nil {
		t.Error("una firma de otra clave NO debe aceptarse")
	}
}

func TestVencida(t *testing.T) {
	ahora := time.Unix(1_000_000, 0)
	if Vencida(1_000_100, ahora) {
		t.Error("una tarea con caducidad futura no esta vencida")
	}
	if !Vencida(999_900, ahora) {
		t.Error("una tarea con caducidad pasada esta vencida")
	}
}

func TestParseInstallMSI(t *testing.T) {
	sha := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	p, err := ParseInstallMSI(`{"url":"https://x/a.msi","sha256":"` + sha + `","args":"/quiet","not_after":123}`)
	if err != nil {
		t.Fatalf("payload valido: %v", err)
	}
	if p.URL == "" || p.SHA256 != sha || p.NotAfter != 123 {
		t.Errorf("campos mal parseados: %+v", p)
	}
	if _, err := ParseInstallMSI(`{"url":"","sha256":"corto"}`); err == nil {
		t.Error("un payload incompleto debe fallar")
	}
}
