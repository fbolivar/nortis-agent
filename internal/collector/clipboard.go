package collector

import (
	"time"

	"github.com/fbolivar/nortis-agent/internal/contract"
)

// POR QUE EL PORTAPAPELES NECESITA UN PROCESO APARTE
//
// El portapapeles pertenece a la ESTACION DE VENTANA, y cada sesion de Windows
// tiene la suya. Desde Windows Vista los servicios corren aislados en la sesion
// 0 y el usuario en la 1 o superior: un servicio que llame a
// AddClipboardFormatListener se suscribe al portapapeles de la sesion 0, que
// esta vacio y que ninguna persona usa jamas.
//
// No hay forma de cruzar esa frontera. OpenWindowStation no abre la estacion de
// otra sesion, y no existe una API que exponga el portapapeles ajeno — es una
// barrera de seguridad del sistema operativo, no un descuido.
//
// Por eso el servicio lanza un proceso auxiliar DENTRO de la sesion del usuario
// (`nortis-agent clipboard-watch`), que observa y reporta por una tuberia con
// nombre. El colector de este archivo es el extremo que corre en el servicio:
// recibe lo que el auxiliar observa y lo convierte en telemetria.
//
// LO QUE NUNCA SALE DE AQUI: el contenido copiado. Se registra el tamaño, el
// formato y las aplicaciones de origen y destino. Saber que salieron 40 KB de la
// aplicacion de nomina hacia el navegador basta para abrir un incidente; guardar
// esos 40 KB convertiria a Nortis en un registrador de teclas con base de datos.

// VentanaRepeticionPortapapeles agrupa copias seguidas desde la misma
// aplicacion.
//
// Copiar y pegar varias celdas de una hoja de calculo produce una rafaga de
// cambios de portapapeles en segundos. Al motor DLP le interesa que hubo
// extraccion desde una fuente protegida, no cuantas veces se pulso Ctrl+C.
const VentanaRepeticionPortapapeles = 30 * time.Second

// copiaPortapapeles es un cambio de portapapeles ya observado por el auxiliar.
type copiaPortapapeles struct {
	// AplicacionOrigen es el proceso dueño del portapapeles: de donde salio.
	AplicacionOrigen string
	Bytes            int64
	// Formato es text, image, file_list u other.
	Formato string
	Usuario string
	Momento time.Time
}

// maquinaPortapapeles agrupa copias y construye los eventos.
type maquinaPortapapeles struct {
	visto map[string]time.Time
}

func nuevaMaquinaPortapapeles() *maquinaPortapapeles {
	return &maquinaPortapapeles{visto: map[string]time.Time{}}
}

// observar convierte una copia en evento, o la descarta por repetida.
//
// `enforcement` lo decide quien llama a partir de la politica: el recolector
// informa de lo que el agente hizo, no interpreta reglas.
func (m *maquinaPortapapeles) observar(c copiaPortapapeles, enforcement string) *contract.Event {
	if c.AplicacionOrigen == "" {
		// Sin aplicacion de origen el evento es inutil para el motor DLP: la
		// regla compara `source_app` contra la lista de fuentes protegidas.
		// Emitirlo solo añadiria ruido que nadie puede accionar.
		return nil
	}

	clave := normalizar(c.AplicacionOrigen) + "|" + c.Usuario
	if ultimo, ok := m.visto[clave]; ok && c.Momento.Sub(ultimo) < VentanaRepeticionPortapapeles {
		return nil
	}
	m.visto[clave] = c.Momento

	payload := map[string]any{
		"source_app":  c.AplicacionOrigen,
		"enforcement": enforcement,
	}
	if c.Formato != "" {
		payload["format"] = c.Formato
	}
	if c.Bytes > 0 {
		payload["bytes"] = c.Bytes
	}
	if c.Usuario != "" {
		payload["user"] = c.Usuario
	}
	if cat := Categoria(c.AplicacionOrigen); cat != "sin clasificar" {
		payload["category"] = cat
	}

	return &contract.Event{
		Type:       contract.EventClipboardCopy,
		OccurredAt: c.Momento,
		Payload:    payload,
	}
}

// FormatoValido acota lo que el auxiliar puede reportar como formato.
//
// El contrato de telemetria solo admite estos cuatro valores; cualquier otro
// hace que la consola descarte el evento entero. Se normaliza aqui para que un
// auxiliar de otra version no tumbe eventos por una cadena inesperada.
func FormatoValido(f string) string {
	switch f {
	case "text", "image", "file_list":
		return f
	default:
		return "other"
	}
}
