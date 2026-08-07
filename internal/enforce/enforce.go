// Package enforce aplica la politica en el endpoint.
//
// Hasta aqui el agente OBSERVABA. Este paquete es el que interviene, y por eso
// se rige por tres reglas que no se negocian:
//
//  1. TODO LO QUE SE CAMBIA SE PUEDE REVERTIR. Se modifica el registro de
//     Windows y el archivo hosts, y esos cambios sobreviven al proceso. Un
//     agente que se desinstala dejando el USB bloqueado no es un producto de
//     seguridad, es una incidencia de soporte. El estado anterior se guarda en
//     disco ANTES de tocar nada, para poder deshacerlo aunque el agente se
//     hubiera caido entre medias.
//
//  2. NO SE TOCA LO QUE NO ES NUESTRO. En el archivo hosts se escribe solo entre
//     dos marcas y se respeta todo lo demas; en el registro se anota si el valor
//     ya existia, para no borrar en la reversion una politica que puso el
//     administrador del cliente.
//
//  3. LO QUE NO SE PUEDE APLICAR SE DICE. Si un control no es alcanzable, se
//     registra como no aplicado en vez de fallar en silencio. Un panel que
//     muestra un equipo "cubierto" cuando no lo esta es peor que uno que admite
//     el hueco.
package enforce

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// MarcaInicio y MarcaFin delimitan el bloque del archivo hosts que gestiona
// Nortis. Todo lo que hay fuera es del cliente y no se toca jamas: en ese
// archivo puede haber entradas de las que depende su red interna.
const (
	MarcaInicio = "# BEGIN NORTIS — gestionado automaticamente, no editar"
	MarcaFin    = "# END NORTIS"
)

// WebmailConocido es la lista que aplica `block_webmail`.
//
// Es la MISMA que evalua el motor DLP de la consola
// (supabase/migrations/…_dlp_detection_engine.sql). Si las dos divergen, el
// agente bloquearia un sitio por el que no se abre incidente, o al reves: se
// abriria un incidente por algo que el agente dejo pasar, y nadie entenderia
// por que.
var WebmailConocido = []string{
	"mail.google.com", "gmail.com", "outlook.com", "outlook.live.com",
	"hotmail.com", "mail.yahoo.com", "proton.me", "mail.proton.me",
	"zoho.com", "mail.com",
}

/* -------------------------------------------------------------- Estado --- */

// Estado es lo que habia ANTES de que Nortis tocara nada.
//
// Se persiste en disco porque la reversion tiene que funcionar aunque el agente
// se haya reiniciado —o caido— entre aplicar y deshacer. Guardarlo solo en
// memoria significaria que un cierre inesperado deja el equipo bloqueado sin que
// nadie sepa como estaba antes.
type Estado struct {
	Aplicado bool `json:"aplicado"`

	// USBStorStart es el valor original de USBSTOR\Start. -1 = no se leyo.
	USBStorStart int `json:"usbstor_start"`
	// WriteProtectLeido dice si YA se anoto el valor previo. Es una marca
	// distinta de WriteProtectExistia, y esa distincion es el punto entero:
	//
	// la politica se reimpone cada pocos minutos, asi que la captura tiene que
	// ocurrir UNA sola vez. Al principio las dos ideas se guardaban en el mismo
	// booleano —"ya lo lei" y "el cliente lo tenia"— y como en la primera pasada
	// el valor no existia, el booleano quedaba en false; en la segunda pasada se
	// volvia a leer y se leia NUESTRO propio 1, que quedaba anotado como el
	// original del cliente. La reversion lo restauraba con toda fidelidad: el
	// USB se quedaba en solo lectura para siempre y el mensaje decia que el
	// equipo habia vuelto a su estado.
	//
	// Paso en un equipo real y hubo que borrar el valor a mano. Por eso son dos
	// campos: uno responde "¿ya miré?" y el otro "¿había algo?".
	WriteProtectLeido bool `json:"write_protect_leido"`
	// WriteProtectExistia indica si el valor ya estaba puesto por el cliente,
	// para no borrar en la reversion algo que no pusimos nosotros.
	WriteProtectExistia  bool   `json:"write_protect_existia"`
	WriteProtectOriginal uint32 `json:"write_protect_original"`

	// DohExistia dice, por navegador, si la politica de DNS-over-HTTPS ya
	// estaba definida antes. Si lo estaba NO se borra: se restaura su valor.
	DohExistia  map[string]bool   `json:"doh_existia"`
	DohOriginal map[string]string `json:"doh_original"`
}

// AnotarWriteProtect registra el valor previo de WriteProtect la PRIMERA vez que
// se llama y no hace nada en las siguientes.
//
// Esta separado del codigo de registro —que solo existe en Windows y necesita
// privilegios— para que la regla de "una sola captura" se pueda probar. Es el
// tipo de logica cuyo fallo no se ve al aplicar la politica sino semanas
// despues, al intentar deshacerla, y para entonces el equipo ya esta bloqueado.
func AnotarWriteProtect(e *Estado, valor uint32, existe bool) {
	if e.WriteProtectLeido {
		return
	}
	e.WriteProtectLeido = true
	e.WriteProtectExistia = existe
	e.WriteProtectOriginal = valor
}

func nuevoEstado() *Estado {
	return &Estado{
		USBStorStart: -1,
		DohExistia:   map[string]bool{},
		DohOriginal:  map[string]string{},
	}
}

// CargarEstado lee el estado guardado, o devuelve uno vacio.
func CargarEstado(dir string) *Estado {
	data, err := os.ReadFile(rutaEstado(dir))
	if err != nil {
		return nuevoEstado()
	}
	e := nuevoEstado()
	if err := json.Unmarshal(data, e); err != nil {
		// Un estado corrupto no puede impedir aplicar la politica; se empieza de
		// cero y se pierde la capacidad de revertir con exactitud, que es mejor
		// que quedarse sin proteccion.
		return nuevoEstado()
	}
	if e.DohExistia == nil {
		e.DohExistia = map[string]bool{}
	}
	if e.DohOriginal == nil {
		e.DohOriginal = map[string]string{}
	}
	return e
}

func (e *Estado) Guardar(dir string) error {
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(rutaEstado(dir), data, 0o600)
}

func rutaEstado(dir string) string { return filepath.Join(dir, "enforce-state.json") }

/* --------------------------------------------------- Archivo hosts (puro) --- */

// DominiosABloquear reune lo que hay que cortar segun la politica.
//
// Devuelve tambien `soloAlerta`: los controles que la politica pide pero que
// esta via no puede aplicar. Hoy es el caso de la LISTA BLANCA — "permitir solo
// estos dominios y bloquear el resto" es imposible con el archivo hosts, que
// solo sabe nombrar lo que se bloquea, no lo que se permite. Se informa en vez
// de fingir que esta cubierto.
func DominiosABloquear(bloqueados, listaBlanca []string, bloquearWebmail bool) (aBloquear []string, soloAlerta []string) {
	vistos := map[string]bool{}
	añadir := func(d string) {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" || vistos[d] {
			return
		}
		vistos[d] = true
		aBloquear = append(aBloquear, d)
	}

	for _, d := range bloqueados {
		añadir(d)
	}
	if bloquearWebmail {
		for _, d := range WebmailConocido {
			añadir(d)
		}
	}

	if len(listaBlanca) > 0 {
		soloAlerta = append(soloAlerta,
			"lista blanca de dominios: no es aplicable con el archivo hosts, que solo sabe bloquear nombres concretos; queda en modo alerta")
	}

	sort.Strings(aBloquear)
	return aBloquear, soloAlerta
}

// ComponerHosts devuelve el contenido nuevo del archivo hosts.
//
// Conserva integro lo que hay fuera de las marcas: en ese archivo puede vivir la
// resolucion de la intranet del cliente, y pisarla dejaria a la empresa sin
// acceso a sus propios sistemas — un agente de seguridad que tumba la red
// interna se desinstala esa misma tarde.
func ComponerHosts(actual string, dominios []string) string {
	base := QuitarBloqueNortis(actual)

	if len(dominios) == 0 {
		return base
	}

	var b strings.Builder
	b.WriteString(base)
	if base != "" && !strings.HasSuffix(base, "\n") {
		b.WriteString("\r\n")
	}
	b.WriteString(MarcaInicio)
	b.WriteString("\r\n")

	for _, d := range dominios {
		// Se bloquea el dominio y su variante con www: el usuario que escribe
		// "wetransfer.com" y el que escribe "www.wetransfer.com" tienen la misma
		// intencion, y dejar una de las dos abierta hace inutil la otra.
		fmt.Fprintf(&b, "0.0.0.0 %s\r\n", d)
		if !strings.HasPrefix(d, "www.") {
			fmt.Fprintf(&b, "0.0.0.0 www.%s\r\n", d)
		}
	}

	b.WriteString(MarcaFin)
	b.WriteString("\r\n")
	return b.String()
}

// QuitarBloqueNortis devuelve el archivo sin la seccion gestionada.
//
// Tolera que falte la marca de cierre: si un editor de texto o un apagon
// dejaron el archivo a medias, se corta desde la marca de inicio hasta el final
// en vez de dejar entradas huerfanas que nadie sabria de donde salieron.
func QuitarBloqueNortis(contenido string) string {
	inicio := strings.Index(contenido, MarcaInicio)
	if inicio < 0 {
		return contenido
	}

	antes := contenido[:inicio]

	fin := strings.Index(contenido[inicio:], MarcaFin)
	if fin < 0 {
		return strings.TrimRight(antes, "\r\n") + "\r\n"
	}

	despues := contenido[inicio+fin+len(MarcaFin):]
	despues = strings.TrimLeft(despues, "\r\n")

	resultado := strings.TrimRight(antes, "\r\n")
	if resultado != "" {
		resultado += "\r\n"
	}
	return resultado + despues
}
