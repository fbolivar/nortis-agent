// Package updater implementa la auto-actualizacion del agente.
//
// El agente consulta periodicamente /api/agent/version (sin credencial). Si la
// consola anuncia una version mas nueva Y adjunta la URL de descarga y su
// sha256, el agente descarga el MSI, VERIFICA el hash y lanza la actualizacion.
// Asi un cambio se publica una vez en la consola y llega a toda la flota sin
// tocar los equipos.
//
// Por que la verificacion es innegociable: el agente corre como LocalSystem y la
// actualizacion reemplaza su propio binario. Aplicar lo que haya al otro lado de
// una URL, sin comprobar nada, es entregar SYSTEM a quien controle esa URL. El
// sha256 es el minimo; en produccion la descarga va por HTTPS y, como
// endurecimiento siguiente, el manifiesto se firma con la MISMA clave Ed25519 de
// la consola que el agente ya fija para la proteccion anti-manipulacion.
package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/rs/zerolog"

	"github.com/fbolivar/nortis-agent/internal/contract"
)

// tamMaxMSI acota la descarga. Un MSI del agente ronda los 5 MB; 200 MB es un
// techo holgado que impide que una respuesta manipulada agote el disco.
const tamMaxMSI = 200 << 20

// FuenteVersion es lo que el updater necesita del cliente HTTP: consultar la
// version. Se abstrae para poder probar el updater sin una consola de verdad.
type FuenteVersion func(context.Context) (contract.VersionResponse, error)

type Updater struct {
	version       FuenteVersion
	versionActual string
	http          *http.Client
	log           zerolog.Logger
}

func New(version FuenteVersion, versionActual string, httpClient *http.Client, log zerolog.Logger) *Updater {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Updater{version: version, versionActual: versionActual, http: httpClient, log: log}
}

// Comprobar mira si hay una version mas nueva y, si la hay y es verificable, la
// aplica. Devuelve true si lanzo una actualizacion (tras lo cual el proceso sera
// reemplazado por el instalador y no deberia seguir trabajando).
func (u *Updater) Comprobar(ctx context.Context) (bool, error) {
	info, err := u.version(ctx)
	if err != nil {
		return false, err
	}

	// download_url/sha256 nulos = actualizacion "armada pero inactiva": la
	// consola aun no publica binario. No es un error, es el estado normal hasta
	// que exista el pipeline de publicacion firmada.
	if info.DownloadURL == nil || info.SHA256 == nil {
		return false, nil
	}
	if !EsMasNueva(info.CurrentVersion, u.versionActual) {
		return false, nil
	}

	u.log.Info().
		Str("actual", u.versionActual).
		Str("disponible", info.CurrentVersion).
		Msg("actualizacion disponible; descargando")

	ruta, err := u.descargarYVerificar(ctx, *info.DownloadURL, *info.SHA256)
	if err != nil {
		return false, fmt.Errorf("descarga/verificacion: %w", err)
	}

	u.log.Warn().
		Str("version", info.CurrentVersion).
		Msg("hash verificado; aplicando actualizacion (el servicio se reiniciara)")

	if err := aplicarMSI(ruta); err != nil {
		return false, fmt.Errorf("aplicando el MSI: %w", err)
	}
	return true, nil
}

// descargarYVerificar baja el instalador a un archivo temporal calculando el
// sha256 al vuelo, y solo lo conserva si coincide con el esperado. Un hash que no
// cuadra se trata como hostil: se borra el archivo y no se aplica nada.
func (u *Updater) descargarYVerificar(ctx context.Context, url, sha256Esperado string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := u.http.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d al descargar el instalador", resp.StatusCode)
	}

	tmp, err := os.CreateTemp("", "nortis-agent-*.msi")
	if err != nil {
		return "", err
	}
	rutaTmp := tmp.Name()

	h := sha256.New()
	// Se escribe en el archivo y en el hash a la vez; el LimitReader impide que
	// una respuesta sin fin llene el disco.
	_, err = io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, tamMaxMSI))
	cerrErr := tmp.Close()
	if err != nil {
		_ = os.Remove(rutaTmp)
		return "", err
	}
	if cerrErr != nil {
		_ = os.Remove(rutaTmp)
		return "", cerrErr
	}

	obtenido := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(obtenido, strings.TrimSpace(sha256Esperado)) {
		_ = os.Remove(rutaTmp)
		return "", fmt.Errorf("sha256 no coincide: esperado %s, obtenido %s", sha256Esperado, obtenido)
	}
	return rutaTmp, nil
}

// EsMasNueva compara dos versiones semanticas (MAYOR.MENOR.PARCHE) y dice si
// `candidata` es estrictamente mayor que `actual`. Ignora sufijos tras un guion
// (p. ej. "0.0.0-dev"): en desarrollo, cualquier version publicada con numero se
// considera mas nueva que la de desarrollo.
func EsMasNueva(candidata, actual string) bool {
	ca := partes(candidata)
	ac := partes(actual)
	for i := 0; i < 3; i++ {
		if ca[i] != ac[i] {
			return ca[i] > ac[i]
		}
	}
	return false
}

func partes(v string) [3]int {
	// Se corta cualquier sufijo de precompilacion: "1.2.3-rc1" -> "1.2.3".
	if i := strings.IndexByte(v, '-'); i >= 0 {
		v = v[:i]
	}
	var out [3]int
	for i, s := range strings.SplitN(v, ".", 3) {
		if i > 2 {
			break
		}
		n, _ := strconv.Atoi(strings.TrimSpace(s))
		out[i] = n
	}
	return out
}
