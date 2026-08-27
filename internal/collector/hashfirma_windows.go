//go:build windows

package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// maxHashBytes evita hashear binarios enormes (instaladores, juegos): por encima
// de esto no se calcula el hash. Un ejecutable normal esta muy por debajo.
const maxHashBytes = 200 << 20 // 200 MB

// sha256Archivo devuelve el SHA-256 en hex del archivo, o "" si no se puede leer
// o es demasiado grande.
func sha256Archivo(ruta string) string {
	if ruta == "" {
		return ""
	}
	fi, err := os.Stat(ruta)
	if err != nil || fi.Size() > maxHashBytes {
		return ""
	}
	f, err := os.Open(ruta)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// firmaAuthenticode devuelve el editor firmante y si la firma es valida. Usa
// Get-AuthenticodeSignature (PowerShell). Devuelve ("", nil) si no se pudo
// determinar. `firmada` es true solo si el estado es Valid.
func firmaAuthenticode(ruta string) (string, *bool) {
	if ruta == "" {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	// Salida: "Estado|Subject". El Subject trae CN=..., O=..., etc.
	script := `$s=Get-AuthenticodeSignature -LiteralPath '` + strings.ReplaceAll(ruta, "'", "''") +
		`' -ErrorAction SilentlyContinue; "$($s.Status)|$($s.SignerCertificate.Subject)"`
	out, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		return "", nil
	}
	partes := strings.SplitN(strings.TrimSpace(string(out)), "|", 2)
	if len(partes) == 0 {
		return "", nil
	}
	estado := strings.TrimSpace(partes[0])
	valida := strings.EqualFold(estado, "Valid")
	editor := ""
	if len(partes) == 2 {
		editor = cnDeSubject(partes[1])
	}
	if estado == "" {
		return editor, nil // no se pudo determinar
	}
	return editor, &valida
}

// cnDeSubject extrae el CN (nombre comun, el editor) de un Subject X.500.
func cnDeSubject(subject string) string {
	for _, campo := range strings.Split(subject, ",") {
		campo = strings.TrimSpace(campo)
		if strings.HasPrefix(strings.ToUpper(campo), "CN=") {
			return strings.TrimSpace(campo[3:])
		}
	}
	return strings.TrimSpace(subject)
}
