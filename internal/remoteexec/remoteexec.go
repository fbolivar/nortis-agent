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
	"path/filepath"
	"strings"
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

// --- push_file: colocar un archivo en el equipo ---

// PushFilePayload es el contenido de una tarea push_file.
type PushFilePayload struct {
	URL      string `json:"url"`
	SHA256   string `json:"sha256"`
	DestPath string `json:"dest_path"`
	NotAfter int64  `json:"not_after"`
}

// ParsePushFile lee y valida el payload de una tarea push_file. Exige una ruta
// destino ABSOLUTA y sin "..": la consola encarga la accion, pero el agente no
// deja que una ruta relativa o con traversal escriba fuera de donde se pretende.
func ParsePushFile(payload string) (PushFilePayload, error) {
	var p PushFilePayload
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		return p, fmt.Errorf("payload push_file ilegible: %w", err)
	}
	if p.URL == "" || len(p.SHA256) != 64 || p.DestPath == "" {
		return p, errors.New("payload push_file incompleto (url/sha256/dest_path)")
	}
	if !filepath.IsAbs(p.DestPath) || strings.Contains(p.DestPath, "..") {
		return p, fmt.Errorf("ruta destino invalida: %q", p.DestPath)
	}
	return p, nil
}

// EjecutarPushFile descarga el archivo (verificando sha256) y lo coloca en
// DestPath, creando la carpeta si falta. Devuelve exito y la ruta final.
func EjecutarPushFile(ctx context.Context, p PushFilePayload) (int, string, error) {
	tmp, err := descargarVerificado(ctx, p.URL, p.SHA256, filepath.Ext(p.DestPath))
	if err != nil {
		return -1, "", err
	}
	// Si el movimiento tiene exito, tmp deja de existir; si falla, se limpia.
	movido := false
	defer func() {
		if !movido {
			_ = os.Remove(tmp)
		}
	}()

	if err := os.MkdirAll(filepath.Dir(p.DestPath), 0o750); err != nil {
		return -1, "", fmt.Errorf("no se pudo crear la carpeta destino: %w", err)
	}
	if err := moverArchivo(tmp, p.DestPath); err != nil {
		return -1, "", err
	}
	movido = true
	return 0, "archivo colocado en " + p.DestPath, nil
}

// moverArchivo mueve src a dst. Intenta os.Rename (instantaneo en el mismo
// volumen) y, si falla porque cruzan de unidad, copia y borra el origen.
func moverArchivo(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	_ = os.Remove(src)
	return nil
}
