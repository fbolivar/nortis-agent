package collector

import (
	"testing"
	"time"
)

// La regla dura del contrato: solo el host, nunca la URL completa. La ruta y la
// cadena de consulta llevan identificadores de sesion y tokens.
func TestSoloSeExtraeElHost(t *testing.T) {
	casos := map[string]string{
		"https://wetransfer.com/downloads/abc123?token=SECRETO": "wetransfer.com",
		"https://mail.google.com/mail/u/0/#inbox":               "mail.google.com",
		"http://www.dian.gov.co/tramites?cedula=79123456":       "www.dian.gov.co",
		"https://SUB.Ejemplo.COM/path":                          "sub.ejemplo.com",
	}

	for entrada, esperado := range casos {
		if got := HostDeURL(entrada); got != esperado {
			t.Errorf("%s -> %q, se esperaba %q", entrada, got, esperado)
		}
	}
}

func TestNavegacionQueNoSaleDelEquipoSeDescarta(t *testing.T) {
	descartables := []string{
		"chrome://settings/privacy",
		"edge://extensions",
		"about:blank",
		`file:///C:/Users/jperez/Documents/informe.pdf`,
		"http://localhost:3000/dashboard",
		"http://127.0.0.1:8080/",
		"http://192.168.1.10/impresora",
		"http://10.0.0.5/erp",
		"http://172.16.4.9/intranet",
		"devtools://devtools/bundled/inspector.html",
		"", // entrada vacia
	}

	for _, u := range descartables {
		if got := HostDeURL(u); got != "" {
			t.Errorf("%s deberia descartarse, devolvio %q", u, got)
		}
	}
}

// Una IP publica SI se reporta: puede ser exfiltracion a un servidor propio.
func TestIPPublicaSeReporta(t *testing.T) {
	if got := HostDeURL("http://203.0.113.9/subir"); got != "203.0.113.9" {
		t.Errorf("una IP publica debe reportarse, se obtuvo %q", got)
	}
}

// Una persona en un sitio genera decenas de entradas de historial. Al motor DLP
// le basta con saber que visito ese dominio.
func TestVisitasAlMismoDominioSeAgrupan(t *testing.T) {
	m := nuevaMaquinaWeb()
	base := time.Date(2026, 8, 7, 16, 0, 0, 0, time.UTC)

	var visitas []visitaWeb
	for i := 0; i < 12; i++ {
		visitas = append(visitas, visitaWeb{
			URL:     "https://wetransfer.com/pagina" + string(rune('a'+i)),
			Momento: base.Add(time.Duration(i) * 10 * time.Second),
			Usuario: "jperez",
		})
	}

	ev := m.observar(visitas, base)
	if len(ev) != 1 {
		t.Fatalf("doce paginas del mismo dominio son un evento, hubo %d", len(ev))
	}
	if ev[0].Payload["domain"] != "wetransfer.com" {
		t.Errorf("domain: %v", ev[0].Payload["domain"])
	}
}

func TestDominiosDistintosSonEventosDistintos(t *testing.T) {
	m := nuevaMaquinaWeb()
	base := time.Date(2026, 8, 7, 16, 0, 0, 0, time.UTC)

	ev := m.observar([]visitaWeb{
		{URL: "https://wetransfer.com/a", Momento: base, Usuario: "jperez"},
		{URL: "https://mail.google.com/b", Momento: base, Usuario: "jperez"},
	}, base)

	if len(ev) != 2 {
		t.Fatalf("dos dominios son dos eventos, hubo %d", len(ev))
	}
}

// Dos personas en el mismo equipo se cuentan por separado: atribuir la
// navegacion de una a la otra seria acusar a quien no fue.
func TestLaAgrupacionEsPorUsuario(t *testing.T) {
	m := nuevaMaquinaWeb()
	base := time.Date(2026, 8, 7, 16, 0, 0, 0, time.UTC)

	ev := m.observar([]visitaWeb{
		{URL: "https://wetransfer.com/a", Momento: base, Usuario: "jperez"},
		{URL: "https://wetransfer.com/b", Momento: base, Usuario: "mlopez"},
	}, base)

	if len(ev) != 2 {
		t.Fatalf("mismo dominio y distinta persona son dos eventos, hubo %d", len(ev))
	}
}

// Confundir el origen de tiempo de Chrome con el de Unix coloca las visitas en
// 1601, y la consola las descarta por quedar fuera de la ventana de retencion —
// en silencio, que es lo peor.
func TestElOrigenDeTiempoDeChromeEsCorrecto(t *testing.T) {
	momento := time.Date(2026, 8, 7, 16, 30, 0, 0, time.UTC)

	ida := aMicrosChrome(momento)
	vuelta := tiempoChrome(ida)

	if !vuelta.Equal(momento) {
		t.Fatalf("ida y vuelta no coinciden: %s -> %d -> %s", momento, ida, vuelta)
	}

	// Y un valor real de Chrome tiene que caer en este siglo, no en el XVII.
	if vuelta.Year() < 2000 {
		t.Fatalf("el origen de tiempo esta mal: %s", vuelta)
	}

	if !tiempoChrome(0).IsZero() {
		t.Error("un tiempo de cero no es una visita valida")
	}
}

func TestUsuarioSeDeduceDeLaRutaDelPerfil(t *testing.T) {
	ruta := `C:\Users\jperez\AppData\Local\Google\Chrome\User Data\Default\History`
	if got := usuarioDeRutaPerfil(ruta); got != "jperez" {
		t.Errorf("usuario: %q", got)
	}
}

func TestPayloadDeNavegacionNoLlevaLaURL(t *testing.T) {
	m := nuevaMaquinaWeb()
	base := time.Now().UTC()

	ev := m.observar([]visitaWeb{{
		URL:       "https://wetransfer.com/downloads/abc?token=SECRETO",
		Momento:   base,
		Navegador: "chrome.exe",
		Usuario:   "jperez",
	}}, base)

	if len(ev) != 1 {
		t.Fatal("deberia emitir")
	}
	p := ev[0].Payload

	if p["domain"] != "wetransfer.com" {
		t.Errorf("domain: %v", p["domain"])
	}
	if p["browser"] != "chrome.exe" {
		t.Errorf("browser: %v", p["browser"])
	}
	if p["category"] != "navegador" {
		t.Errorf("category: %v", p["category"])
	}

	// Ni la URL, ni la ruta, ni el token pueden aparecer por ninguna via.
	for clave, valor := range p {
		if s, ok := valor.(string); ok {
			if s == "SECRETO" || containsFold(s, "token") || containsFold(s, "/downloads") {
				t.Errorf("el payload filtro parte de la URL en %q: %q", clave, s)
			}
		}
	}
	if _, hay := p["url"]; hay {
		t.Error("el payload no puede llevar la URL completa")
	}
}
