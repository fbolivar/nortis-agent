package collector

import (
	"strings"
	"time"

	"github.com/fbolivar/nortis-agent/internal/contract"
)

// volumen es una unidad extraible vista en un sondeo.
type volumen struct {
	// Letra de unidad, sin barra: "E:".
	Letra string
	// Serial del DISPOSITIVO, leido del descriptor de almacenamiento. Es el que
	// sobrevive a un formateo, y por tanto el unico util para una lista blanca.
	Serial string
	// SerialVolumen es el numero de serie del SISTEMA DE ARCHIVOS. Cambia al
	// formatear; solo se usa como respaldo cuando el dispositivo no expone el
	// suyo (lectores de tarjetas baratos, algunos adaptadores USB-SATA).
	SerialVolumen string
	Etiqueta      string
	CapacidadByte uint64
	Usuario       string
}

// SerialEfectivo es lo que viaja como `serial` en la telemetria.
//
// La lista blanca de la politica se compara contra ESTE valor, asi que la
// eleccion importa: el serial de dispositivo identifica la memoria concreta y
// sobrevive a un formateo; el del volumen se lo lleva por delante cualquiera con
// un clic derecho. Usar el segundo por defecto convertiria la lista blanca en un
// control que se salta formateando la memoria.
//
// Cuando no hay serial de dispositivo se antepone "vol:" al de respaldo, para
// que quien lea un incidente sepa que esta viendo un identificador debil y no
// crea que autorizo un dispositivo cuando autorizo un formato.
func (v volumen) SerialEfectivo() string {
	if v.Serial != "" {
		return v.Serial
	}
	if v.SerialVolumen != "" {
		return "vol:" + v.SerialVolumen
	}
	return ""
}

// claveVolumen identifica un dispositivo entre sondeos.
//
// Se usa el serial y NO la letra de unidad: Windows reasigna letras, asi que
// desconectar y reconectar la misma memoria en otro puerto la haria pasar por
// un dispositivo distinto — y con ello duplicaria el incidente. Si no hay
// serial de ninguna clase se cae a la letra, que es mejor que no detectar nada.
func (v volumen) clave() string {
	if s := v.SerialEfectivo(); s != "" {
		return s
	}
	return "letra:" + strings.ToUpper(v.Letra)
}

// maquinaUSB convierte sondeos de volumenes en eventos de conexion.
//
// Pura y sin llamadas al sistema, igual que las de sesiones y aplicaciones: las
// transiciones son donde viven los errores que inundan la cola de eventos
// repetidos, y aqui se pueden probar sin enchufar una memoria.
type maquinaUSB struct {
	presentes map[string]bool
}

func nuevaMaquinaUSB() *maquinaUSB {
	return &maquinaUSB{presentes: map[string]bool{}}
}

// observar emite un usb_connected por cada dispositivo nuevo.
//
// `enforcement` lo decide quien llama a partir de la politica vigente: el
// recolector no interpreta reglas, solo informa de lo que hizo el agente. Un
// recolector que decidiera por su cuenta acabaria discrepando del modulo que
// aplica la politica, y el panel mostraria una accion que no ocurrio.
func (m *maquinaUSB) observar(vols []volumen, enforcement string, ahora time.Time) []contract.Event {
	actual := make(map[string]bool, len(vols))
	var eventos []contract.Event

	for _, v := range vols {
		k := v.clave()
		actual[k] = true

		if m.presentes[k] {
			continue
		}

		payload := map[string]any{
			"label":       v.Etiqueta,
			"enforcement": enforcement,
		}
		if s := v.SerialEfectivo(); s != "" {
			payload["serial"] = s
		}
		if v.CapacidadByte > 0 {
			payload["capacity_bytes"] = v.CapacidadByte
		}
		if v.Usuario != "" {
			payload["user"] = v.Usuario
		}

		eventos = append(eventos, contract.Event{
			Type:       contract.EventUSBConnected,
			OccurredAt: ahora,
			Payload:    payload,
		})
	}

	// Los que ya no estan se olvidan, para que volver a conectarlos genere un
	// evento nuevo. Una memoria que entra y sale tres veces en una tarde son
	// tres oportunidades de sacar informacion, no una.
	m.presentes = actual
	return eventos
}
