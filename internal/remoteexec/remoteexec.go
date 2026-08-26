// Package remoteexec ejecuta las tareas administrativas que la consola encarga
// (instalar un MSI, colocar un archivo, reiniciar). La regla de oro: NADA se
// ejecuta sin verificar antes la firma Ed25519 de la consola sobre los bytes
// canonicos de la tarea. El agente no confia en la base ni en la API — solo en la
// clave privada de la consola, que no vive en ninguna de las dos.
package remoteexec

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// signPrefix y la construccion de BytesCanonicos DEBEN coincidir byte a byte con
// la consola (src/shared/lib/agent-signing.ts). Si divergen, ninguna firma
// verifica.
const signPrefix = "nortis-task-v1"

// BytesCanonicos son los bytes exactos sobre los que se calcula/verifica la
// firma: prefijo, endpoint, tipo y el payload TAL CUAL llego (los mismos bytes
// que la consola guardo y firmo).
func BytesCanonicos(endpointID, kind, payload string) []byte {
	return []byte(signPrefix + "\n" + endpointID + "\n" + kind + "\n" + payload)
}

// VerificarFirma comprueba la firma Ed25519 de la consola. Es la unica puerta:
// si devuelve error, la tarea NO se ejecuta.
func VerificarFirma(pub ed25519.PublicKey, endpointID, kind, payload, firmaB64 string) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("clave publica de la consola no disponible o invalida")
	}
	firma, err := base64.StdEncoding.DecodeString(firmaB64)
	if err != nil {
		return fmt.Errorf("la firma no es base64 valido: %w", err)
	}
	if !ed25519.Verify(pub, BytesCanonicos(endpointID, kind, payload), firma) {
		return errors.New("firma invalida: la tarea no la emitio la consola")
	}
	return nil
}

// InstallMSIPayload es el contenido de una tarea install_msi.
type InstallMSIPayload struct {
	URL      string `json:"url"`
	SHA256   string `json:"sha256"`
	Args     string `json:"args"`
	NotAfter int64  `json:"not_after"` // epoch en segundos; caducidad firmada
}

// ParseInstallMSI lee y valida el payload de una tarea install_msi.
func ParseInstallMSI(payload string) (InstallMSIPayload, error) {
	var p InstallMSIPayload
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		return p, fmt.Errorf("payload install_msi ilegible: %w", err)
	}
	if p.URL == "" || len(p.SHA256) != 64 {
		return p, errors.New("payload install_msi incompleto (url/sha256)")
	}
	return p, nil
}

// Vencida indica si la caducidad firmada ya paso. Una tarea vencida se rechaza
// aunque la firma sea valida: acota la reejecucion de una tarea copiada.
func Vencida(notAfter int64, ahora time.Time) bool {
	return notAfter > 0 && ahora.Unix() > notAfter
}

// descargarVerificado baja `url` a un archivo temporal con extension `ext` y
// comprueba que su sha256 coincide con `shaHex`. Si no coincide, borra el archivo
// y devuelve error: nunca se ejecuta un binario sin verificar su integridad.
// Devuelve la ruta del archivo temporal (el llamante debe borrarlo).
func descargarVerificado(ctx context.Context, url, shaHex, ext string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("descarga fallida: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("descarga devolvio HTTP %d", resp.StatusCode)
	}

	f, err := os.CreateTemp("", "nortis-task-*"+ext)
	if err != nil {
		return "", err
	}
	tmp := f.Name()

	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return "", fmt.Errorf("no se pudo escribir la descarga: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}

	got := hex.EncodeToString(h.Sum(nil))
	if got != shaHex {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("sha256 no coincide: esperado %s, obtenido %s", shaHex, got)
	}
	return tmp, nil
}
