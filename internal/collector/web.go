package collector

import (
	"net/url"
	"strings"
	"time"

	"github.com/fbolivar/nortis-agent/internal/contract"
)

// POR QUE EL HISTORIAL DEL NAVEGADOR Y NO OTRA COSA
//
// Las tres reglas de navegacion del motor DLP (dominio bloqueado, webmail,
// fuera de lista blanca) comparan contra el HOST que visito la persona. Habia
// cuatro formas de obtenerlo y ninguna es obvia:
//
//   - Extension de navegador. Es la que mas informacion da y la unica que ve la
//     URL completa. Pero exige publicar y mantener una extension por navegador,
//     forzar su instalacion por politica de grupo, y se desactiva desde el
//     propio navegador — un control de seguridad que el vigilado puede apagar
//     con dos clics no es un control.
//
//   - Driver WFP en modo kernel. Ve todo el trafico, incluido el que no pasa por
//     un navegador. Exige certificado EV mas atestacion de Microsoft, y un fallo
//     en modo kernel es una pantalla azul en el equipo del cliente. Es un
//     proyecto propio, no un recolector.
//
//   - Registro de consultas DNS. No necesita driver ni extension, pero mide otra
//     cosa: una consulta a mail.google.com ocurre tambien cuando una pestaña de
//     fondo se refresca sola, y el canal del registro viene desactivado de
//     fabrica. Generaria incidentes por sitios que nadie visito.
//
//   - HISTORIAL DEL NAVEGADOR. Es lo que se implementa. Registra visitas REALES
//     —hubo intencion de navegar—, no ruido de fondo; funciona sin driver, sin
//     extension y sin que el usuario pueda desactivarlo desde el navegador; y
//     Chrome, Edge y Brave comparten esquema, asi que un solo lector cubre la
//     practica totalidad del parque de una PYME colombiana.
//
// EL PRECIO, que hay que tener presente: la deteccion no es instantanea. El
// navegador escribe su historial por lotes, asi que una visita puede tardar
// segundos o algun minuto en aparecer. Para DLP eso es aceptable —el incidente
// se abre igual— pero NO sirve para bloquear en el momento. El bloqueo por
// dominio se aplica por otra via (DNS/hosts), no desde aqui.

// VentanaRepeticionWeb agrupa visitas al mismo dominio.
//
// Una persona en un sitio genera decenas de entradas de historial en minutos.
// Al motor DLP le basta con saber que visito ese dominio; una fila por cada
// pagina interna solo infla la cola y el incidente cuenta ocurrencias que no
// significan nada.
const VentanaRepeticionWeb = 10 * time.Minute

// visitaWeb es una entrada de historial ya leida.
type visitaWeb struct {
	URL       string
	Momento   time.Time
	Navegador string
	Usuario   string
}

// esquemasIgnorados son URL que no son navegacion a un sitio.
var esquemasIgnorados = map[string]bool{
	"chrome": true, "edge": true, "brave": true, "about": true,
	"file": true, "data": true, "javascript": true, "blob": true,
	"chrome-extension": true, "extension": true, "moz-extension": true,
	"devtools": true, "view-source": true,
}

// hostsIgnorados es navegacion local, que no sale del equipo.
var hostsIgnorados = map[string]bool{
	"localhost": true, "127.0.0.1": true, "::1": true, "0.0.0.0": true,
}

// HostDeURL extrae el host de una URL, o "" si no procede reportarla.
//
// SOLO EL HOST, NUNCA LA URL COMPLETA. Es una regla dura del contrato de
// telemetria y no una preferencia: la ruta y la cadena de consulta llevan
// identificadores de sesion, tokens y a veces credenciales. Guardar la URL
// entera convertiria la base de Nortis en el mayor deposito de secretos del
// cliente, que es exactamente el riesgo que el producto dice mitigar.
func HostDeURL(crudo string) string {
	u, err := url.Parse(strings.TrimSpace(crudo))
	if err != nil || u.Host == "" {
		return ""
	}

	if esquemasIgnorados[strings.ToLower(u.Scheme)] {
		return ""
	}

	host := strings.ToLower(u.Hostname())
	if host == "" || hostsIgnorados[host] {
		return ""
	}

	// Direcciones IP privadas: es trafico interno de la empresa, no salida de
	// informacion. Reportarlo llenaria la consola de la propia intranet.
	if esIPPrivada(host) {
		return ""
	}

	return host
}

func esIPPrivada(host string) bool {
	switch {
	case strings.HasPrefix(host, "10."),
		strings.HasPrefix(host, "192.168."),
		strings.HasPrefix(host, "169.254."):
		return true
	}
	// 172.16.0.0 – 172.31.255.255
	if strings.HasPrefix(host, "172.") {
		resto := host[4:]
		punto := strings.IndexByte(resto, '.')
		if punto > 0 {
			seg := resto[:punto]
			if len(seg) == 2 && seg[0] == '1' && seg[1] >= '6' && seg[1] <= '9' {
				return true
			}
			if len(seg) == 2 && seg[0] == '2' {
				return true
			}
			if len(seg) == 2 && seg[0] == '3' && seg[1] <= '1' {
				return true
			}
		}
	}
	return false
}

/* ------------------------------------------------- Maquina de estado --- */

type claveWeb struct {
	Usuario string
	Dominio string
}

// maquinaWeb convierte visitas de historial en eventos, agrupando por dominio.
type maquinaWeb struct {
	visto map[claveWeb]time.Time
}

func nuevaMaquinaWeb() *maquinaWeb {
	return &maquinaWeb{visto: map[claveWeb]time.Time{}}
}

// observar devuelve los eventos que corresponden a un lote de visitas.
func (m *maquinaWeb) observar(visitas []visitaWeb, ahora time.Time) []contract.Event {
	var out []contract.Event

	for _, v := range visitas {
		dominio := HostDeURL(v.URL)
		if dominio == "" {
			continue
		}

		k := claveWeb{Usuario: v.Usuario, Dominio: dominio}
		if ultimo, ok := m.visto[k]; ok && v.Momento.Sub(ultimo) < VentanaRepeticionWeb {
			continue
		}
		m.visto[k] = v.Momento

		payload := map[string]any{"domain": dominio}
		if v.Navegador != "" {
			payload["browser"] = v.Navegador
		}
		if v.Usuario != "" {
			payload["user"] = v.Usuario
		}
		if c := Categoria(v.Navegador); c != "sin clasificar" {
			payload["category"] = c
		}

		out = append(out, contract.Event{
			Type:       contract.EventWebVisit,
			OccurredAt: v.Momento,
			Payload:    payload,
		})
	}

	m.limpiar(ahora)
	return out
}

func (m *maquinaWeb) limpiar(ahora time.Time) {
	if len(m.visto) < 4096 {
		return
	}
	for k, t := range m.visto {
		if ahora.Sub(t) > VentanaRepeticionWeb {
			delete(m.visto, k)
		}
	}
}

/* ------------------------------------------------------------ Utiles --- */

// Viven aqui y no en el archivo _windows porque son manipulacion de cadenas sin
// una sola llamada al sistema: en este paquete lo puro se separa de los syscalls
// precisamente para poder probarlo, y una funcion detras de una etiqueta de
// compilacion solo se puede probar en una plataforma.

func toLowerASCII(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

func containsFold(s, sub string) bool {
	if sub == "" || len(s) < len(sub) {
		return false
	}
	ls, lsub := toLowerASCII(s), toLowerASCII(sub)
	for i := 0; i+len(lsub) <= len(ls); i++ {
		if ls[i:i+len(lsub)] == lsub {
			return true
		}
	}
	return false
}

// usuarioDeRutaPerfil deduce la persona a partir de C:\Users\<quien>\...
//
// Se saca de la RUTA y no de la sesion activa a proposito: el historial
// pertenece al dueño del perfil. Si dos personas comparten el equipo, atribuir
// la navegacion de una a la que esta delante en ese momento seria acusar a quien
// no fue — y en un producto que sirve de evidencia, eso es lo unico que no se
// puede permitir.
func usuarioDeRutaPerfil(ruta string) string {
	partes := splitRuta(ruta)
	for i := 0; i+1 < len(partes); i++ {
		if toLowerASCII(partes[i]) == "users" {
			return partes[i+1]
		}
	}
	return ""
}

func splitRuta(p string) []string {
	var out []string
	actual := ""
	for _, r := range p {
		if r == '\\' || r == '/' {
			if actual != "" {
				out = append(out, actual)
				actual = ""
			}
			continue
		}
		actual += string(r)
	}
	if actual != "" {
		out = append(out, actual)
	}
	return out
}

/* ------------------------------------------------------------- Tiempo --- */

// Chrome cuenta microsegundos desde 1601-01-01 UTC —el mismo origen que FILETIME
// de Windows, dividido entre diez— y no desde el epoch de Unix. Confundirlos
// coloca las visitas en otro siglo y la consola las descarta por quedar fuera de
// la ventana de retencion, EN SILENCIO: el agente creeria estar reportando y no
// habria ni un error que mirar.
//
// segundosEntre1601Y1970 es la distancia entre los dos origenes.
const segundosEntre1601Y1970 = 11644473600

// La conversion NO puede pasar por time.Duration.
//
// Duration es un int64 de NANOSEGUNDOS, y de 1601 a hoy hay unos 1.3e19: mas de
// lo que cabe en un int64, que llega a 9.2e18. `t.Sub(epoca)` se satura en el
// maximo y devuelve una fecha del siglo XIX sin avisar de nada. Toda la
// aritmetica se hace en microsegundos sobre el epoch de Unix, donde los numeros
// son pequeños y no hay desbordamiento posible.

func tiempoChrome(micros int64) time.Time {
	if micros <= 0 {
		return time.Time{}
	}
	return time.UnixMicro(micros - segundosEntre1601Y1970*1_000_000).UTC()
}

func aMicrosChrome(t time.Time) int64 {
	return t.UTC().UnixMicro() + segundosEntre1601Y1970*1_000_000
}

// webmailConocidos son dominios de correo web habituales, para la regla
// block_webmail. La lista es corta y explicita a proposito: mejor no bloquear un
// webmail raro que bloquear por error algo que no lo es.
var webmailConocidos = []string{
	"mail.google.com", "gmail.com", "outlook.live.com", "outlook.office365.com",
	"outlook.office.com", "mail.yahoo.com", "proton.me", "mail.proton.me",
	"correo.google.com", "zoho.com", "mail.com",
}

// DominioBloqueado decide si un dominio esta bloqueado por la politica, y por
// que motivo. La coincidencia es por sufijo de dominio: "eltiempo.com" bloquea
// "www.eltiempo.com" pero no "noeltiempo.com".
//
// Es la mitad portable de la notificacion #1: separa la DECISION —probada aqui—
// del aviso en pantalla, que es puro Windows.
func DominioBloqueado(dominio string, p *contract.Policy) (bool, string) {
	if p == nil || dominio == "" {
		return false, ""
	}
	d := toLowerASCII(dominio)

	for _, b := range p.Web.BlockedDomains {
		if coincideDominio(d, toLowerASCII(b)) {
			return true, "restringido por la politica de seguridad"
		}
	}
	if p.Web.BlockWebmail {
		for _, w := range webmailConocidos {
			if coincideDominio(d, w) {
				return true, "correo web restringido por la politica de seguridad"
			}
		}
	}
	// Lista blanca: con allowed_domains, todo lo que no este dentro se bloquea.
	if len(p.Web.AllowedDomains) > 0 {
		for _, a := range p.Web.AllowedDomains {
			if coincideDominio(d, toLowerASCII(a)) {
				return false, ""
			}
		}
		return true, "fuera de la lista de sitios permitidos"
	}
	return false, ""
}

func coincideDominio(dominio, patron string) bool {
	if patron == "" {
		return false
	}
	return dominio == patron || strings.HasSuffix(dominio, "."+patron)
}
