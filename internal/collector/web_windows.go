//go:build windows

package collector

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/sys/windows"
	_ "modernc.org/sqlite"

	"github.com/fbolivar/nortis-agent/internal/contract"
)

// IntervaloWeb es cada cuanto se revisa el historial.
//
// 30 segundos es un compromiso: mas frecuente no adelanta nada porque el
// navegador escribe su historial por lotes, y menos frecuente retrasaria el
// incidente sin ahorrar trabajo real —copiar un historial es leer unos pocos
// megabytes.
const IntervaloWeb = 30 * time.Second

// navegador describe donde vive el historial de un navegador concreto.
type navegador struct {
	Nombre string
	// Proceso es el ejecutable, para poder clasificarlo y reportarlo.
	Proceso string
	// Relativo a la carpeta del perfil de usuario.
	SubrutaDatos string
}

// Chrome, Edge y Brave son el mismo navegador por dentro: comparten el esquema
// de historial de Chromium, asi que un solo lector los cubre a los tres.
//
// Firefox NO esta: usa places.sqlite, con otro esquema y otro origen de tiempo.
// Se deja fuera a proposito en vez de a medias — un lector que devuelva fechas
// equivocadas es peor que no leer ese navegador, porque la consola descartaria
// las visitas en silencio y nadie sabria que falta la mitad.
var navegadoresChromium = []navegador{
	{Nombre: "Chrome", Proceso: "chrome.exe", SubrutaDatos: `AppData\Local\Google\Chrome\User Data`},
	{Nombre: "Edge", Proceso: "msedge.exe", SubrutaDatos: `AppData\Local\Microsoft\Edge\User Data`},
	{Nombre: "Brave", Proceso: "brave.exe", SubrutaDatos: `AppData\Local\BraveSoftware\Brave-Browser\User Data`},
}

// WebCollector reporta los dominios visitados leyendo el historial.
//
// Enciende tres reglas del motor DLP: dominio bloqueado (alta), webmail
// bloqueado (alta) y fuera de lista blanca (baja).
type WebCollector struct {
	log     zerolog.Logger
	maquina *maquinaWeb

	// politica da acceso a la politica vigente, para saber que dominios estan
	// bloqueados y avisar al usuario cuando visite uno.
	politica PoliticaVigente

	// marca es, por archivo de historial, la ultima visita ya reportada.
	marca map[string]time.Time
	// notificados evita repetir el aviso del mismo dominio en cada ciclo.
	notificados map[string]time.Time
}

func NewWebCollector(log zerolog.Logger, politica PoliticaVigente) *WebCollector {
	return &WebCollector{
		log:         log.With().Str("recolector", "web").Logger(),
		maquina:     nuevaMaquinaWeb(),
		politica:    politica,
		marca:       map[string]time.Time{},
		notificados: map[string]time.Time{},
	}
}

func (c *WebCollector) Name() string { return "web" }

func (c *WebCollector) Run(ctx context.Context, emit Emit) {
	// LA MARCA ARRANCA EN "AHORA". Es una decision deliberada y no una
	// simplificacion: al instalarse, el agente NO vuelca el historial de
	// navegacion pasado de la persona. Nortis vigila desde que se instala, no
	// hacia atras. Volcar meses de navegacion anterior seria tratar datos que
	// nadie autorizo al firmar el consentimiento, y ademas llenaria la consola
	// de incidentes por sitios visitados antes de que existiera la politica.
	inicio := time.Now().UTC()
	for _, ruta := range c.historiales() {
		c.marca[ruta] = inicio
	}
	c.log.Debug().Int("historiales", len(c.marca)).Msg("navegacion: se vigila desde ahora, no hacia atras")

	t := time.NewTicker(IntervaloWeb)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.revisar(ctx, emit, inicio)
		}
	}
}

func (c *WebCollector) revisar(ctx context.Context, emit Emit, inicio time.Time) {
	for _, ruta := range c.historiales() {
		if ctx.Err() != nil {
			return
		}

		desde, ok := c.marca[ruta]
		if !ok {
			// Historial que aparece despues de arrancar: un perfil de navegador
			// nuevo, o un usuario que inicio sesion. Tampoco se vuelca su pasado.
			desde = inicio
			c.marca[ruta] = desde
		}

		visitas, err := c.leer(ruta, desde)
		if err != nil {
			c.log.Debug().Err(err).Str("historial", ruta).Msg("no se pudo leer el historial")
			continue
		}
		if len(visitas) == 0 {
			continue
		}

		for _, v := range visitas {
			if v.Momento.After(c.marca[ruta]) {
				c.marca[ruta] = v.Momento
			}
		}

		var pol *contract.Policy
		if c.politica != nil {
			pol = c.politica()
		}

		for _, e := range c.maquina.observar(visitas, time.Now().UTC()) {
			// Si el dominio esta bloqueado por la politica, se marca el evento y
			// se avisa al usuario con un mensaje corporativo. El bloqueo en si lo
			// aplica el enforcement (archivo hosts); esto lo hace VISIBLE en vez
			// de dejar al usuario ante un error de navegador sin explicacion.
			if dom, _ := e.Payload["domain"].(string); dom != "" {
				if bloq, motivo := DominioBloqueado(dom, pol); bloq {
					e.Payload["blocked"] = true
					c.notificarBloqueo(dom, motivo)
				}
			}
			emit(e)
		}
	}
}

// historiales localiza los archivos de historial de todos los usuarios.
func (c *WebCollector) historiales() []string {
	var out []string

	usuarios := unidadSistema() + `\Users`
	entradas, err := os.ReadDir(usuarios)
	if err != nil {
		return nil
	}

	for _, e := range entradas {
		if !e.IsDir() {
			continue
		}
		switch e.Name() {
		case "Public", "Default", "Default User", "All Users":
			continue
		}
		perfil := filepath.Join(usuarios, e.Name())

		for _, nav := range navegadoresChromium {
			datos := filepath.Join(perfil, nav.SubrutaDatos)
			perfilesNav, err := os.ReadDir(datos)
			if err != nil {
				continue
			}
			for _, pn := range perfilesNav {
				if !pn.IsDir() {
					continue
				}
				h := filepath.Join(datos, pn.Name(), "History")
				if st, err := os.Stat(h); err == nil && !st.IsDir() {
					out = append(out, h)
				}
			}
		}
	}
	return out
}

// leer devuelve las visitas posteriores a `desde`.
//
// SE TRABAJA SOBRE UNA COPIA. El navegador mantiene el historial abierto y
// bloqueado, asi que abrirlo directamente falla o —peor— podria interferir con
// la escritura del propio navegador. Copiarlo es unos milisegundos y elimina el
// riesgo de estorbar a la aplicacion del usuario, que es una linea que el agente
// no puede cruzar.
func (c *WebCollector) leer(ruta string, desde time.Time) ([]visitaWeb, error) {
	tmp, err := os.CreateTemp("", "nortis-hist-*.db")
	if err != nil {
		return nil, err
	}
	tmpRuta := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpRuta)

	if err := copiarArchivo(ruta, tmpRuta); err != nil {
		return nil, err
	}

	// `mode=ro` y `immutable=1`: se abre en solo lectura y se le dice a SQLite
	// que nadie mas va a tocar la copia, con lo que no intenta crear archivos
	// de journal junto a ella.
	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?mode=ro&immutable=1", tmpRuta))
	if err != nil {
		return nil, err
	}
	defer db.Close()

	filas, err := db.Query(`
		select u.url, v.visit_time
		  from visits v join urls u on u.id = v.url
		 where v.visit_time > ?
		 order by v.visit_time asc
		 limit 500`,
		aMicrosChrome(desde),
	)
	if err != nil {
		return nil, err
	}
	defer filas.Close()

	navProceso := procesoDelNavegador(ruta)
	usuario := usuarioDeRutaPerfil(ruta)

	var out []visitaWeb
	for filas.Next() {
		var (
			u      string
			micros int64
		)
		if err := filas.Scan(&u, &micros); err != nil {
			return nil, err
		}
		momento := tiempoChrome(micros)
		if momento.IsZero() {
			continue
		}
		out = append(out, visitaWeb{
			URL:       u,
			Momento:   momento,
			Navegador: navProceso,
			Usuario:   usuario,
		})
	}
	return out, filas.Err()
}

// procesoDelNavegador deduce que navegador escribio ese historial a partir de su
// ruta. Se reporta el ejecutable y no el nombre comercial porque es lo que el
// resto de la telemetria usa como identificador de aplicacion.
func procesoDelNavegador(ruta string) string {
	for _, nav := range navegadoresChromium {
		if containsFold(ruta, nav.SubrutaDatos) {
			return nav.Proceso
		}
	}
	return ""
}

func copiarArchivo(origen, destino string) error {
	// FILE_SHARE_* amplio via os.Open: el navegador tiene el archivo abierto y
	// hay que poder leerlo mientras escribe.
	in, err := os.Open(origen)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(destino, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

// notificarBloqueo muestra al usuario, en SU sesion, un aviso de que el dominio
// esta bloqueado. Deduplica por dominio para no repetir el mismo aviso en cada
// ciclo, y no hace nada si no hay nadie con sesion interactiva delante.
func (c *WebCollector) notificarBloqueo(dominio, motivo string) {
	ahora := time.Now()
	if t, ok := c.notificados[dominio]; ok && ahora.Sub(t) < VentanaRepeticionWeb {
		return
	}
	c.notificados[dominio] = ahora

	token, err := tokenDeSesionActiva()
	if err != nil {
		// Nadie con sesion interactiva (arranque, o servidor sin usuario): no hay
		// a quien avisar. No es un error.
		return
	}
	defer token.Close()

	exe, err := os.Executable()
	if err != nil {
		return
	}

	titulo := "Nortis - Acceso bloqueado"
	mensaje := fmt.Sprintf("El sitio %s esta %s.\n\nSi cree que es un error, contacte con el area de seguridad.", dominio, motivo)

	cmd := exec.Command(exe, "notify", "-title", titulo, "-message", mensaje)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Token:         syscall.Token(token),
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW,
	}
	if err := cmd.Start(); err != nil {
		c.log.Debug().Err(err).Str("dominio", dominio).Msg("no se pudo mostrar el aviso de bloqueo")
		return
	}
	// No se espera: el aviso vive en la sesion del usuario hasta que lo cierre.
	// Se libera el proceso hijo en segundo plano para no dejar zombis.
	go func() { _ = cmd.Wait() }()
}
