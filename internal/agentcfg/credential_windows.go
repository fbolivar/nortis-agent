//go:build windows

package agentcfg

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/fbolivar/nortis-agent/internal/dpapi"
)

// Los dos formatos que maneja el agente, con prefijos distintos a proposito
// para que una no pueda usarse en lugar de la otra ni por accidente.
//
// Validarlos aqui evita guardar una credencial mal copiada y descubrirlo tres
// dias despues, cuando alguien note que ese equipo nunca reporto.
var (
	// La clave de la ORGANIZACION. Solo sirve para el alta.
	apiKeyPattern = regexp.MustCompile(`^nrt_live_[0-9a-f]{64}$`)
	// La credencial de ESTE equipo, que devuelve el alta.
	endpointCredPattern = regexp.MustCompile(`^nrt_ep_[0-9a-f]{64}$`)
)

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

// HasCredential indica si queda guardada la clave de la organizacion.
//
// NO significa "el agente esta enrolado": tras un alta correcta esta clave se
// borra a proposito. Para saber si el agente esta operativo, HasEndpointCredential.
func HasCredential() bool {
	_, err := os.Stat(CredentialPath())
	return err == nil
}

/* -------------------------------------------- Credencial de este equipo --- */

// SaveEndpointCredential cifra con DPAPI la credencial propia del equipo.
//
// Se guarda en un archivo distinto del de la clave de la organizacion porque
// tienen ciclos de vida opuestos: la del equipo dura toda la vida de la
// instalacion, la de la organizacion se destruye en cuanto sobra.
func SaveEndpointCredential(cred string) error {
	cred = strings.TrimSpace(cred)
	if !endpointCredPattern.MatchString(cred) {
		return fmt.Errorf("la credencial del equipo no tiene el formato esperado (nrt_ep_ + 64 hex)")
	}

	if err := EnsureDir(); err != nil {
		return err
	}

	blob, err := dpapi.Protect([]byte(cred))
	if err != nil {
		return fmt.Errorf("protegiendo la credencial del equipo: %w", err)
	}

	return os.WriteFile(EndpointCredentialPath(), blob, 0o600)
}

// LoadEndpointCredential descifra la credencial propia del equipo.
func LoadEndpointCredential() (string, error) {
	blob, err := os.ReadFile(EndpointCredentialPath())
	if os.IsNotExist(err) {
		return "", fmt.Errorf("el agente no esta enrolado: falta la credencial del equipo")
	}
	if err != nil {
		return "", fmt.Errorf("leyendo la credencial del equipo: %w", err)
	}

	plain, err := dpapi.Unprotect(blob)
	if err != nil {
		// Ocurre si el disco se clono a otra maquina. Es el comportamiento
		// deseado —una credencial no debe sobrevivir a la clonacion de un
		// disco— pero el mensaje tiene que decir que hacer.
		return "", fmt.Errorf("no se pudo descifrar la credencial en esta maquina; vuelva a enrolar el agente: %w", err)
	}

	return string(plain), nil
}

// HasEndpointCredential indica si el agente esta enrolado y operativo.
func HasEndpointCredential() bool {
	_, err := os.Stat(EndpointCredentialPath())
	return err == nil
}

// DiscardOrganizationKey borra la clave de la organizacion tras un alta
// correcta.
//
// ES EL PASO QUE CIERRA EL AGUJERO. Mientras esa clave siga en el disco, quien
// tome el portatil puede enrolar equipos nuevos y —antes del cambio de contrato—
// escribir telemetria como cualquier otro equipo del cliente. Ya no hace falta
// para nada: todo lo que el agente hace a partir del alta va firmado con la
// credencial propia.
//
// El precio: volver a enrolar exige tener la clave de la organizacion otra vez,
// es decir, pasar por el instalador. Es el intercambio correcto — reinstalar es
// una operacion administrativa puntual; dejar la llave maestra del cliente en
// doscientos discos, no.
func DiscardOrganizationKey() error {
	err := os.Remove(CredentialPath())
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
