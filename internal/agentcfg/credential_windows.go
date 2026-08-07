//go:build windows

package agentcfg

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/fbolivar/nortis-agent/internal/dpapi"
)

// apiKeyPattern es el formato exacto que produce create_api_key en la consola.
// Validarlo aqui evita guardar una credencial mal copiada y descubrirlo tres
// dias despues, cuando alguien note que ese equipo nunca reporto.
var apiKeyPattern = regexp.MustCompile(`^nrt_live_[0-9a-f]{64}$`)

// SaveCredential cifra la API key con DPAPI y la escribe en disco.
func SaveCredential(apiKey string) error {
	apiKey = strings.TrimSpace(apiKey)
	if !apiKeyPattern.MatchString(apiKey) {
		return fmt.Errorf("la credencial no tiene el formato esperado (nrt_live_ + 64 hex)")
	}

	if err := EnsureDir(); err != nil {
		return err
	}

	blob, err := dpapi.Protect([]byte(apiKey))
	if err != nil {
		return fmt.Errorf("protegiendo la credencial: %w", err)
	}

	// 0600 es lo que Go puede expresar; los permisos NTFS reales los fija el
	// instalador (solo SYSTEM y Administradores). En Windows el modo de Go es
	// una aproximacion, no el control efectivo — conviene no confiarse.
	return os.WriteFile(CredentialPath(), blob, 0o600)
}

// LoadCredential descifra la API key.
func LoadCredential() (string, error) {
	blob, err := os.ReadFile(CredentialPath())
	if os.IsNotExist(err) {
		return "", fmt.Errorf("el agente no esta enrolado: falta la credencial")
	}
	if err != nil {
		return "", fmt.Errorf("leyendo la credencial: %w", err)
	}

	plain, err := dpapi.Unprotect(blob)
	if err != nil {
		// Ocurre si el disco se clono a otra maquina o si el perfil cambio. Es
		// el comportamiento deseado, pero el mensaje tiene que decir que hacer.
		return "", fmt.Errorf("no se pudo descifrar la credencial en esta maquina; vuelva a enrolar el agente: %w", err)
	}

	return string(plain), nil
}

// HasCredential indica si el agente ya fue enrolado.
func HasCredential() bool {
	_, err := os.Stat(CredentialPath())
	return err == nil
}
