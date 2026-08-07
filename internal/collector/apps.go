package collector

import (
	"time"

	"github.com/fbolivar/nortis-agent/internal/contract"
)

// proceso es un proceso observado en una sesion interactiva.
type proceso struct {
	PID       uint32
	Exe       string
	SessionID uint32
	Ruta      string
	Usuario   string
}

// MaxAppsPorSondeo limita cuantos app_open se emiten en un solo sondeo.
//
// Un inicio de sesion arranca decenas de programas a la vez; sin tope, un
// arranque masivo o un fallo de la lista de ruido podria meter cientos de
// eventos de golpe en la cola. Lo que se descarta se registra en el log, nunca
// en silencio.
const MaxAppsPorSondeo = 50

// claveApp identifica una aplicacion por sesion, no por PID.
//
// Por PID el reporte seria inutil: Chrome arranca un proceso por pestaña y cada
// una generaria su propio app_open. Lo que interesa registrar es "esta persona
// abrio Chrome", una vez.
type claveApp struct {
	Sesion uint32
	Exe    string
}

// maquinaApps convierte sondeos de procesos en eventos de apertura.
//
// Pura, sin llamadas al sistema, por la misma razon que la de sesiones: las
// transiciones son donde estan los errores que inundan la cola.
type maquinaApps struct {
	previo map[claveApp]bool
}

func nuevaMaquinaApps() *maquinaApps {
	return &maquinaApps{previo: map[claveApp]bool{}}
}

// conocido indica si esa aplicacion ya se vio en esa sesion.
//
// Lo usa el lado de Windows para no resolver la ruta del ejecutable de procesos
// que no va a reportar: abrir cada proceso para preguntarle su ruta, en cada
// sondeo y para los doscientos que tiene un Windows normal, es trabajo tirado.
func (m *maquinaApps) conocido(sesion uint32, exe string) bool {
	return m.previo[claveApp{Sesion: sesion, Exe: normalizar(exe)}]
}

// observar devuelve un app_open por cada aplicacion nueva y descarta las que ya
// no estan, de modo que volver a abrirlas genere un evento nuevo.
func (m *maquinaApps) observar(procesos []proceso, ahora time.Time) (eventos []contract.Event, descartados int) {
	actual := make(map[claveApp]proceso, len(procesos))

	for _, p := range procesos {
		if esRuidoDelSistema(p.Exe) {
			continue
		}
		k := claveApp{Sesion: p.SessionID, Exe: normalizar(p.Exe)}
		// Se queda el primero visto: en un Chrome con veinte procesos, el
		// primero suele ser el padre, que es el que tiene la ruta buena.
		if _, ya := actual[k]; !ya {
			actual[k] = p
		}
	}

	for k, p := range actual {
		if m.previo[k] {
			continue
		}
		if len(eventos) >= MaxAppsPorSondeo {
			descartados++
			continue
		}
		payload := map[string]any{
			"app":      p.Exe,
			"category": Categoria(p.Exe),
		}
		if p.Ruta != "" {
			payload["executable_path"] = p.Ruta
		}
		if p.Usuario != "" {
			payload["user"] = p.Usuario
		}
		eventos = append(eventos, contract.Event{
			Type:       contract.EventAppOpen,
			OccurredAt: ahora,
			Payload:    payload,
		})
	}

	// Se reemplaza el estado en vez de acumularlo: una app que se cerro tiene
	// que desaparecer para que reabrirla vuelva a contar como apertura, y para
	// que el mapa no crezca sin limite en un equipo que lleve meses encendido.
	nuevo := make(map[claveApp]bool, len(actual))
	for k := range actual {
		// Lo que se descarto por el tope se marca igualmente como visto: si no,
		// el siguiente sondeo lo reintentaria y el tope no serviria de nada.
		nuevo[k] = true
	}
	m.previo = nuevo

	return eventos, descartados
}

// ruidoDelSistema son procesos que Windows arranca por su cuenta en la sesion
// del usuario.
//
// No los abrio nadie, asi que reportarlos como "aplicacion abierta" seria falso
// y ademas ahogaria en la lista los programas que la persona si abrio. La lista
// es de nombres exactos y no de rutas a proposito: un binario con uno de estos
// nombres fuera de System32 es justo lo que hay que ver, y aunque aqui se filtre
// por nombre, esos casos los cubre la vigilancia de procesos de la Fase 2.
var ruidoDelSistema = map[string]bool{
	"runtimebroker.exe": true, "dllhost.exe": true, "sihost.exe": true,
	"ctfmon.exe": true, "taskhostw.exe": true, "searchhost.exe": true,
	"startmenuexperiencehost.exe": true, "shellexperiencehost.exe": true,
	"applicationframehost.exe": true, "systemsettings.exe": true,
	"textinputhost.exe": true, "lockapp.exe": true, "useroobebroker.exe": true,
	"smartscreen.exe": true, "securityhealthsystray.exe": true,
	"widgets.exe": true, "widgetservice.exe": true, "phoneexperiencehost.exe": true,
	"crossdeviceservice.exe": true, "backgroundtaskhost.exe": true,
	"wmiprvse.exe": true, "conhost.exe": true, "fontdrvhost.exe": true,
	"dwm.exe": true, "csrss.exe": true, "winlogon.exe": true, "userinit.exe": true,
	"rundll32.exe": true, "wermgr.exe": true, "werfault.exe": true,
	"msedgewebview2.exe": true, // motor incrustado en otras apps, no un navegador abierto
	"nortis-agent.exe":   true, // el agente no se reporta a si mismo
}

func esRuidoDelSistema(exe string) bool {
	return ruidoDelSistema[normalizar(exe)]
}
