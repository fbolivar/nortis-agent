// Package contract define los tipos que viajan entre el agente y la consola.
//
// Es el espejo en Go de lo que la consola declara en TypeScript:
//   - src/shared/schemas/agent-api.ts  (peticiones y respuestas HTTP)
//   - src/shared/schemas/telemetry.ts  (forma del payload de cada evento)
//   - src/shared/schemas/policy.ts     (forma de la politica)
//
// Cualquier cambio aqui tiene que corresponderse con un cambio alli. Cuando los
// dos lados divergen, el sintoma no es un error de compilacion sino telemetria
// que la consola descarta en silencio — por eso el sincronizador registra
// siempre cuantos eventos fueron rechazados y por que.
package contract

import "time"

// AgentVersion es la version que el agente reporta y con la que se compara
// contra minimum_supported_version de la consola.
//
// Es una VARIABLE, no una constante, para que el empaquetado la fije con
// -ldflags -X a la misma version que lleva el MSI. Siendo constante, todo
// binario reportaba el mismo numero pasara lo que pasara: la consola veria la
// misma version en un parque con tres versiones distintas instaladas, y el aviso
// de agente desactualizado no se disparaba nunca.
//
// El valor de aqui es solo el de una compilacion de desarrollo. 0.0.0 y no un
// numero que parezca real: si algun dia llega a produccion sin sellar, tiene que
// cantar en el panel en vez de pasar por una version legitima.
var AgentVersion = "1.0.0"

// PolicySchemaVersion es la version del contrato de politica que este agente
// SABE aplicar.
//
// Si la consola devuelve un schema_version mayor, el agente NO debe aplicar la
// politica a medias: sigue con la ultima que conoce y se reporta desactualizado.
// Aplicar la mitad de una politica de seguridad es peor que no aplicarla,
// porque el panel mostraria el equipo como cubierto cuando no lo esta.
const PolicySchemaVersion = 1

/* -------------------------------------------------------------- Eventos --- */

// EventType es el tipo de un evento de telemetria. La lista debe coincidir con
// el enum event_type de Postgres: un valor desconocido hace que la fila entera
// se rechace en la escritura.
type EventType string

const (
	EventAppOpen       EventType = "app_open"
	EventFileCreated   EventType = "file_created"
	EventFileModified  EventType = "file_modified"
	EventFileDeleted   EventType = "file_deleted"
	EventUSBConnected  EventType = "usb_connected"
	EventWebVisit      EventType = "web_visit"
	EventClipboardCopy EventType = "clipboard_copy"
	EventPrintJob      EventType = "print_job"
	EventWindowFocus   EventType = "window_focus"
	EventLogon         EventType = "logon"
	EventLogoff        EventType = "logoff"
	EventIdleStart     EventType = "idle_start"
	EventIdleEnd       EventType = "idle_end"
)

// Event es una unidad de telemetria.
//
// Payload va como map y no como struct tipado a proposito: cada tipo de evento
// tiene su forma, y un struct con todos los campos de todos los tipos obligaria
// a emitir decenas de campos vacios en cada evento. La consola valida la forma
// contra el esquema que corresponde al tipo.
//
// REGLA QUE NO SE PUEDE ROMPER: aqui nunca entra CONTENIDO. Rutas, dominios,
// nombres de proceso y tamaños; nunca el texto de un archivo, el cuerpo de un
// correo ni lo que el usuario copio al portapapeles. Nortis prueba QUE ocurrio
// un movimiento de informacion, no lo reproduce.
type Event struct {
	Type       EventType `json:"event_type"`
	OccurredAt time.Time `json:"occurred_at"`

	// ClientEventID es lo que hace idempotente la ingesta.
	//
	// Se genera UNA vez, al entrar el evento en la cola, y se conserva intacto
	// en cada reintento. Esa permanencia ES el mecanismo: la consola mantiene un
	// indice unico sobre (endpoint_id, client_event_id, occurred_at) y descarta
	// lo que ya recibio, contandolo como aceptado.
	//
	// Regenerarlo al reenviar anularia la deduplicacion por completo y
	// devolveria el problema original: un lote que el servidor confirma y cuya
	// respuesta se pierde se insertaria dos veces. Con portatiles y conectividad
	// intermitente ese es el caso normal, no el raro.
	ClientEventID string `json:"client_event_id"`

	Payload map[string]any `json:"payload,omitempty"`
}

/* ------------------------------------------------------------ Peticiones --- */

type EnrollRequest struct {
	MachineFingerprint string `json:"machine_fingerprint"`
	Hostname           string `json:"hostname"`
	OSVersion          string `json:"os_version,omitempty"`
	AgentVersion       string `json:"agent_version,omitempty"`
	User               string `json:"user,omitempty"`
}

type EnrollResponse struct {
	EndpointID     string `json:"endpoint_id"`
	ProfileID      string `json:"profile_id"`
	OrganizationID string `json:"organization_id"`

	// AgentCredential es la credencial PROPIA de este equipo (nrt_ep_…). Viaja
	// en claro una sola vez, aqui: en la consola solo queda su hash.
	//
	// A partir de este momento es la unica credencial que sirve para ingerir,
	// latir y pedir politica. La clave de la organizacion queda reducida a lo
	// que deberia haber sido siempre — un pase de un solo uso para el alta— y el
	// agente la borra del disco en cuanto termina de enrolarse.
	//
	// El motivo no es cosmetico: antes la MISMA clave vivia en cada portatil de
	// la flota, y quien extrajera la de un solo equipo podia falsear telemetria
	// de cualquier otro. En un producto que sirve de evidencia, eso invalidaba
	// el producto entero.
	AgentCredential string `json:"agent_credential"`
}

type IngestRequest struct {
	EndpointID string  `json:"endpoint_id"`
	Events     []Event `json:"events"`
}

// IngestResponse informa cuantos eventos entraron y cuantos no.
//
// Rejected NO es un error: la consola descarta eventos individuales sin tumbar
// el lote (por ejemplo, con fecha fuera de la ventana de retencion). El agente
// debe darlos por enviados igualmente — reintentarlos produciria un bucle
// infinito sobre eventos que nunca van a entrar.
type IngestResponse struct {
	Accepted int `json:"accepted"`
	Rejected int `json:"rejected"`

	// Duplicates va INCLUIDO en Accepted; se informa aparte solo para
	// diagnostico. Un valor alto y sostenido significa que este agente no esta
	// purgando su cola tras confirmar un lote — es decir, que reenvia lo mismo
	// una y otra vez. Sin este dato ese fallo es invisible desde ambos lados.
	Duplicates int `json:"duplicates"`

	Details []struct {
		Index  int    `json:"index"`
		Reason string `json:"reason"`
	} `json:"details,omitempty"`
}

type PolicyRequest struct {
	EndpointID string `json:"endpoint_id"`
}

// PolicyResponse. Profile puede ser nil: significa que el equipo no tiene perfil
// asignado. En ese caso el agente observa pero NO interviene — inventarse una
// politica permisiva o restrictiva seria tomar por el cliente una decision que
// no tomo.
type PolicyResponse struct {
	Profile *struct {
		ID            string    `json:"id"`
		Name          string    `json:"name"`
		SchemaVersion int       `json:"schema_version"`
		Config        Policy    `json:"config"`
		UpdatedAt     time.Time `json:"updated_at"`
	} `json:"profile"`
	MonitoringAllowed    bool `json:"monitoring_allowed"`
	ConsoleSchemaVersion int  `json:"console_schema_version"`
}

type HeartbeatRequest struct {
	EndpointID   string `json:"endpoint_id"`
	AgentVersion string `json:"agent_version,omitempty"`
	User         string `json:"user,omitempty"`
}

type HeartbeatResponse struct {
	Acknowledged bool `json:"acknowledged"`
	// PolicyUpdatedAt permite saber si hay que volver a descargar la politica
	// sin pedirla entera en cada latido.
	PolicyUpdatedAt *time.Time `json:"policy_updated_at"`
	Quarantined     bool       `json:"quarantined"`
}

type VersionResponse struct {
	CurrentVersion          string  `json:"current_version"`
	MinimumSupportedVersion string  `json:"minimum_supported_version"`
	PolicySchemaVersion     int     `json:"policy_schema_version"`
	DownloadURL             *string `json:"download_url"`
	SHA256                  *string `json:"sha256"`
}

// APIError es la forma uniforme de error de la consola. El agente decide que
// hacer por Code, nunca por el texto del mensaje.
type APIError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

/* -------------------------------------------------------------- Politica --- */

// Policy es la configuracion que el agente aplica. Espejo de policyConfigSchema.
type Policy struct {
	Storage struct {
		// Vacio significa SIN RESTRICCION, no "prohibido todo". Lo segundo
		// dejaria al usuario sin poder trabajar en cuanto alguien creara un
		// perfil a medias.
		AllowedPaths      []string `json:"allowed_paths"`
		BlockedExtensions []string `json:"blocked_extensions"`
	} `json:"storage"`

	USB struct {
		Mode            USBMode  `json:"mode"`
		SerialAllowlist []string `json:"serial_allowlist"`
		// RequireEncryption: si esta activo, una memoria SIN BitLocker se expulsa
		// (no hay solo-lectura por dispositivo en modo usuario; expulsar es la via
		// decisiva). El estado de cifrado lo determina el recolector al montar.
		RequireEncryption bool `json:"require_encryption"`
	} `json:"usb"`

	Web struct {
		BlockedDomains []string `json:"blocked_domains"`
		// Si tiene elementos funciona como lista blanca: todo lo demas se bloquea.
		AllowedDomains []string `json:"allowed_domains"`
		BlockWebmail   bool     `json:"block_webmail"`
	} `json:"web"`

	Clipboard struct {
		Mode             ClipboardMode `json:"mode"`
		ProtectedSources []string      `json:"protected_sources"`
	} `json:"clipboard"`

	Printing struct {
		Mode PrintingMode `json:"mode"`
	} `json:"printing"`

	Encryption struct {
		ConfidentialPaths []string `json:"confidential_paths"`
	} `json:"encryption"`

	// FIM: rutas de archivos a vigilar por integridad (hash). Vacio = el agente
	// usa su lista fija de archivos criticos del sistema.
	FIM struct {
		Paths []string `json:"paths"`
	} `json:"fim"`

	// Monitoring solo llega activo si el tenant tiene consentimiento firmado: la
	// consola recorta estos campos antes de enviarlos. El agente NO debe
	// activarlos por su cuenta bajo ninguna circunstancia.
	Monitoring struct {
		WindowTitles bool `json:"window_titles"`
		Screenshots  bool `json:"screenshots"`
	} `json:"monitoring"`

	// Session gobierna el bloqueo de la sesion por inactividad. Se aplica por la
	// politica de inactividad de Windows (el propio SO bloquea), no por un daemon
	// del agente: asi funciona igual en consola y por RDP. 0 = sin bloqueo
	// gestionado por Nortis (no se toca la configuracion del equipo).
	Session struct {
		LockAfterMinutes int `json:"lock_after_minutes"`
	} `json:"session"`

	// Network gobierna el bloqueo de conexiones. El cableado NUNCA se bloquea: es
	// el enlace por el que se administra el equipo, y cortarlo lo dejaria
	// incomunicado y fuera de alcance. WiFi/celular se restringen SOLO cuando hay
	// cable activo (Windows Connection Manager: si el cable cae, reconectan
	// solos). Bluetooth se deshabilita por servicio.
	Network struct {
		MinimizeWhenWired bool `json:"minimize_when_wired"`
		BlockNonDomain    bool `json:"block_non_domain"`
		BlockBluetooth    bool `json:"block_bluetooth"`
	} `json:"network"`

	// Classification gobierna que hacer cuando un archivo se etiqueta con una de
	// las clases VIGILADAS (por contenido o metadato). Con modo 'quarantine' el
	// agente RETIRA el archivo a cuarentena —recuperable— aunque estuviera en una
	// carpeta permitida: se protege el dato por su clase, no por donde cae. Con
	// 'alert' solo se abre el incidente. Watched vacio = no aplica.
	Classification struct {
		Watched []string           `json:"watched"`
		Mode    ClassificationMode `json:"mode"`
	} `json:"classification"`

	// Apps gobierna el control de aplicaciones. Con un modo distinto de allow, un
	// proceso de la blocklist dispara un incidente ('alert') y, en 'block', el
	// agente lo TERMINA. Es mitigacion, no prevencion: el proceso alcanza a
	// arrancar y se cierra enseguida (modo usuario, sin driver de kernel).
	Apps struct {
		Mode      AppsMode `json:"mode"`
		Blocklist []string `json:"blocklist"`
		// Allowlist es la lista blanca del modo 'allowlist': solo estos ejecutables
		// se permiten. AllowlistEnforce decide si los demas se CIERRAN (true) o
		// solo se alertan (false, modo seguro para probar).
		Allowlist        []string `json:"allowlist"`
		AllowlistEnforce bool     `json:"allowlist_enforce"`
		// BlockUnsigned: trata como no autorizada cualquier app SIN firma valida
		// (aplica el modo vigente: alerta o cierra). Los ejecutables de blocklist
		// y allowlist pueden nombrarse por .exe, por SHA-256 o por editor firmante.
		BlockUnsigned bool `json:"block_unsigned"`
	} `json:"apps"`

	// WorkHours restringe el uso del equipo a un horario. Fuera de la franja (en
	// los dias marcados) el agente bloquea la sesion cada minuto: el usuario no
	// puede trabajar fuera de horario. Days: 1=lunes..7=domingo. Start/End: "HH:MM".
	WorkHours struct {
		Enabled bool   `json:"enabled"`
		Days    []int  `json:"days"`
		Start   string `json:"start"`
		End     string `json:"end"`
	} `json:"work_hours"`

	// Devices controla la instalacion de dispositivos por CLASE (camara, telefonos
	// MTP, CD/DVD, lectores de tarjetas). El agente lo impone por la directiva de
	// Windows "Device Installation Restrictions": una clase denegada no se instala,
	// y las ya conectadas de esa clase se deshabilitan. Prevencion real, sin driver.
	Devices struct {
		BlockCamera     bool `json:"block_camera"`
		BlockPortable   bool `json:"block_portable"`
		BlockCdDvd      bool `json:"block_cd_dvd"`
		BlockCardReader bool `json:"block_card_reader"`
	} `json:"devices"`
}

type AppsMode string

const (
	AppsAllow     AppsMode = "allow"
	AppsAlert     AppsMode = "alert"
	AppsBlock     AppsMode = "block"
	AppsAllowlist AppsMode = "allowlist"
)

type ClassificationMode string

const (
	ClassificationAlert      ClassificationMode = "alert"
	ClassificationQuarantine ClassificationMode = "quarantine"
)

type USBMode string

const (
	USBAllow    USBMode = "allow"
	USBReadOnly USBMode = "read_only"
	USBBlock    USBMode = "block"
)

type ClipboardMode string

const (
	ClipboardAllow ClipboardMode = "allow"
	ClipboardAlert ClipboardMode = "alert"
	ClipboardBlock ClipboardMode = "block"
)

type PrintingMode string

const (
	PrintingAllow PrintingMode = "allow"
	PrintingLog   PrintingMode = "log"
	PrintingBlock PrintingMode = "block"
)

// --- Canal de comandos consola -> agente (restauracion de cuarentena) ---

// PollComandosRequest pide los comandos pendientes de este equipo.
type PollComandosRequest struct {
	EndpointID string `json:"endpoint_id"`
}

// Comando es una accion que la consola encarga al agente.
type Comando struct {
	ID           string `json:"id"`
	Kind         string `json:"kind"` // restore_file | delete_quarantine
	QuarantineID string `json:"quarantine_id"`
	OriginalPath string `json:"original_path"`
}

// PollComandosResponse es la lista de comandos pendientes.
type PollComandosResponse struct {
	Commands []Comando `json:"commands"`
}

// ReportarComandoRequest informa el resultado de ejecutar un comando.
type ReportarComandoRequest struct {
	EndpointID string `json:"endpoint_id"`
	CommandID  string `json:"command_id"`
	Status     string `json:"status"` // done | failed
	Error      string `json:"error,omitempty"`
}

// --- Canal de tareas consola -> agente (ejecucion remota administrada) ---

// PollTareasRequest pide las tareas pendientes de este equipo.
type PollTareasRequest struct {
	EndpointID string `json:"endpoint_id"`
}

// Tarea es una accion administrativa FIRMADA que la consola encarga al agente.
// El agente verifica `Signature` (Ed25519 de la consola) sobre los bytes
// canonicos antes de ejecutar nada; sin firma valida no se ejecuta.
type Tarea struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"` // install_msi | push_file | restart
	Payload   string `json:"payload"`
	ExpiresAt string `json:"expires_at"`
	Signature string `json:"signature"`
}

// PollTareasResponse es la lista de tareas pendientes.
type PollTareasResponse struct {
	Tasks []Tarea `json:"tasks"`
}

// ReportarTareaRequest informa el resultado de ejecutar una tarea.
type ReportarTareaRequest struct {
	EndpointID string `json:"endpoint_id"`
	TaskID     string `json:"task_id"`
	Status     string `json:"status"` // running | done | failed
	ExitCode   *int   `json:"exit_code,omitempty"`
	Output     string `json:"output,omitempty"`
	Error      string `json:"error,omitempty"`
}

// --- Clasificacion de datos por contenido (Fase B) ---

// ClasificacionesRequest pide las reglas de contenido del equipo.
type ClasificacionesRequest struct {
	EndpointID string `json:"endpoint_id"`
}

// Clasificacion es una etiqueta con sus patrones de contenido (regex). El agente
// los evalua localmente y reporta solo la etiqueta.
type Clasificacion struct {
	Name            string   `json:"name"`
	ContentPatterns []string `json:"content_patterns"`
}

// ClasificacionesResponse es el juego de reglas de contenido vigente.
type ClasificacionesResponse struct {
	Classifications []Clasificacion `json:"classifications"`
}

// --- Inventario de software y hardware ---

// SoftwareItem es un programa instalado. Solo metadatos: nombre, version,
// publicador; nunca rutas ni contenido.
type SoftwareItem struct {
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Publisher string `json:"publisher,omitempty"`
}

// InventoryRequest reporta el inventario completo del equipo. El software se
// REEMPLAZA en el servidor con esta lista (un programa desinstalado desaparece).
type InventoryRequest struct {
	EndpointID string         `json:"endpoint_id"`
	Hardware   map[string]any `json:"hardware"`
	Software   []SoftwareItem `json:"software"`
}

// --- Captura de pantalla (monitoreo con consentimiento) ---

// ScreenshotRequest sube una captura de pantalla en base64. Solo se envia si la
// politica trae screenshots=true, que la consola unicamente entrega con
// consentimiento firmado del tenant.
type ScreenshotRequest struct {
	EndpointID  string `json:"endpoint_id"`
	ImageBase64 string `json:"image_base64"`
}

// --- Recuperacion de copia sombra de evidencia (bajo consentimiento) ---

// EvidenceRequest sube la copia sombra de un archivo copiado a un USB. Es
// CONTENIDO, asi que este camino esta gateado por consentimiento firmado, igual
// que las capturas. ContentBase64 vacio = el agente no encontro la copia.
type EvidenceRequest struct {
	EndpointID    string `json:"endpoint_id"`
	EvidenceID    string `json:"evidence_id"`
	OriginalPath  string `json:"original_path,omitempty"`
	ContentBase64 string `json:"content_base64"`
}
