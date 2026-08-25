//go:build windows

package collector

import (
	"context"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/rs/zerolog"
	"golang.org/x/sys/windows"

	"github.com/fbolivar/nortis-agent/internal/contract"
)

// PrintCollector registra —y opcionalmente cancela— los trabajos de impresion.
//
// Enciende la regla print.trabajo_intervenido. Es la de menor severidad de las
// siete, pero cierra un canal de salida que en una PYME sigue siendo real: lo
// que no se puede enviar por correo se imprime y se saca en la mano.
//
// SOBRE LLAMAR A ESTO "BLOQUEAR", con honestidad: hay una carrera que no se
// puede eliminar desde modo usuario. Entre que el trabajo entra en la cola y que
// lo cancelamos, la impresora puede haber recibido ya las primeras paginas. Se
// cancela en cuanto aparece —decimas de segundo— asi que un documento largo se
// corta casi entero, pero uno de una pagina puede salir. La consola debe decirlo:
// prometer bloqueo total de impresion seria mentir.
type PrintCollector struct {
	log      zerolog.Logger
	politica func() *contract.Policy

	// vistos son los identificadores de trabajo ya procesados, para no
	// reportarlos en cada sondeo mientras siguen en la cola.
	vistos map[claveTrabajo]time.Time
}

type claveTrabajo struct {
	Impresora string
	ID        uint32
}

func NewPrintCollector(log zerolog.Logger, politica func() *contract.Policy) *PrintCollector {
	return &PrintCollector{
		log:      log.With().Str("recolector", "impresion").Logger(),
		politica: politica,
		vistos:   map[claveTrabajo]time.Time{},
	}
}

func (c *PrintCollector) Name() string { return "impresion" }

// IntervaloImpresion es cada cuanto se mira la cola.
//
// Medio segundo es un compromiso con la carrera descrita arriba: mas rapido
// gasta CPU en un bucle que casi siempre encuentra la cola vacia, y mas lento
// deja salir mas paginas antes de cancelar.
const IntervaloImpresion = 500 * time.Millisecond

func (c *PrintCollector) Run(ctx context.Context, emit Emit) {
	t := time.NewTicker(IntervaloImpresion)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.revisar(emit)
		}
	}
}

func (c *PrintCollector) modo() contract.PrintingMode {
	if c.politica == nil {
		return contract.PrintingAllow
	}
	p := c.politica()
	if p == nil || p.Printing.Mode == "" {
		return contract.PrintingAllow
	}
	return p.Printing.Mode
}

func (c *PrintCollector) revisar(emit Emit) {
	modo := c.modo()
	if modo == contract.PrintingAllow {
		// En modo permitir NO se registra nada. El contrato de politica dice que
		// `allow` es "no se registran los trabajos de impresion": vigilar de
		// todos modos seria recolectar sin base, y en un producto sujeto a la
		// Ley 1581 eso no es un detalle.
		return
	}

	ahora := time.Now().UTC()
	c.limpiar(ahora)

	for _, impresora := range impresoras() {
		for _, t := range trabajos(impresora) {
			k := claveTrabajo{Impresora: impresora, ID: t.ID}
			if _, visto := c.vistos[k]; visto {
				continue
			}
			c.vistos[k] = ahora

			aplicado := string(contract.PrintingLog)
			if modo == contract.PrintingBlock {
				if err := cancelarTrabajo(impresora, t.ID); err != nil {
					c.log.Error().Err(err).
						Str("impresora", impresora).
						Str("documento", t.Documento).
						Msg("no se pudo cancelar el trabajo de impresion; salio impreso")
					// Se reporta lo que REALMENTE paso. Un incidente que diga
					// "bloqueado" sobre un documento que esta en la bandeja de
					// salida es peor que uno que admita que solo se registro.
					aplicado = string(contract.PrintingLog)
				} else {
					c.log.Warn().
						Str("impresora", impresora).
						Str("documento", t.Documento).
						Msg("trabajo de impresion cancelado por politica")
					aplicado = string(contract.PrintingBlock)
				}
			}

			payload := map[string]any{
				"printer":     impresora,
				"enforcement": aplicado,
			}
			// El NOMBRE del documento, nunca su contenido: prueba que se imprimio
			// la nomina sin guardar la nomina.
			if t.Documento != "" {
				payload["document"] = t.Documento
			}
			if t.Paginas > 0 {
				payload["pages"] = int(t.Paginas)
			}
			if t.Usuario != "" {
				payload["user"] = t.Usuario
			}

			emit(contract.Event{
				Type:       contract.EventPrintJob,
				OccurredAt: ahora,
				Payload:    payload,
			})
		}
	}
}

// limpiar descarta trabajos antiguos del mapa para que no crezca sin fin en un
// agente que lleva semanas encendido.
func (c *PrintCollector) limpiar(ahora time.Time) {
	if len(c.vistos) < 512 {
		return
	}
	for k, t := range c.vistos {
		if ahora.Sub(t) > 10*time.Minute {
			delete(c.vistos, k)
		}
	}
}

/* ------------------------------------------------- API del spooler --- */

var (
	winspool          = windows.NewLazySystemDLL("winspool.drv")
	procEnumPrintersW = winspool.NewProc("EnumPrintersW")
	procOpenPrinterW  = winspool.NewProc("OpenPrinterW")
	procClosePrinter  = winspool.NewProc("ClosePrinter")
	procEnumJobsW     = winspool.NewProc("EnumJobsW")
	procSetJobW       = winspool.NewProc("SetJobW")
)

const (
	printerEnumLocal       = 0x00000002
	printerEnumConnections = 0x00000004
	jobControlDelete       = 5
)

type printerInfo2 struct {
	ServerName         *uint16
	PrinterName        *uint16
	ShareName          *uint16
	PortName           *uint16
	DriverName         *uint16
	Comment            *uint16
	Location           *uint16
	DevMode            uintptr
	SepFile            *uint16
	PrintProcessor     *uint16
	Datatype           *uint16
	Parameters         *uint16
	SecurityDescriptor uintptr
	Attributes         uint32
	Priority           uint32
	DefaultPriority    uint32
	StartTime          uint32
	UntilTime          uint32
	Status             uint32
	Jobs               uint32
	AveragePPM         uint32
}

type jobInfo1 struct {
	JobID        uint32
	PrinterName  *uint16
	MachineName  *uint16
	UserName     *uint16
	Document     *uint16
	Datatype     *uint16
	Status       *uint16
	StatusCode   uint32
	Priority     uint32
	Position     uint32
	TotalPages   uint32
	PagesPrinted uint32
	Submitted    windows.Systemtime
}

type trabajo struct {
	ID        uint32
	Documento string
	Usuario   string
	Paginas   uint32
}

func impresoras() []string {
	var necesario, devueltos uint32

	// Primera llamada para saber cuanta memoria hace falta. Siempre falla con
	// ERROR_INSUFFICIENT_BUFFER; es el protocolo de esta API.
	procEnumPrintersW.Call(
		uintptr(printerEnumLocal|printerEnumConnections), 0, 2,
		0, 0, uintptr(unsafe.Pointer(&necesario)), uintptr(unsafe.Pointer(&devueltos)),
	)
	if necesario == 0 {
		return nil
	}

	buf := make([]byte, necesario)
	r, _, _ := procEnumPrintersW.Call(
		uintptr(printerEnumLocal|printerEnumConnections), 0, 2,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(necesario),
		uintptr(unsafe.Pointer(&necesario)), uintptr(unsafe.Pointer(&devueltos)),
	)
	if r == 0 || devueltos == 0 {
		return nil
	}

	infos := unsafe.Slice((*printerInfo2)(unsafe.Pointer(&buf[0])), devueltos)
	out := make([]string, 0, devueltos)
	for _, i := range infos {
		if i.PrinterName != nil {
			nombre := windows.UTF16PtrToString(i.PrinterName)
			// Las impresoras virtuales que solo generan archivos no son un canal
			// de salida fisico, pero SI lo son de informacion: "Imprimir en PDF"
			// produce un archivo que despues se puede enviar. Se vigilan igual.
			if nombre != "" {
				out = append(out, nombre)
			}
		}
	}
	return out
}

func trabajos(impresora string) []trabajo {
	nombre, err := windows.UTF16PtrFromString(impresora)
	if err != nil {
		return nil
	}

	var h windows.Handle
	if r, _, _ := procOpenPrinterW.Call(
		uintptr(unsafe.Pointer(nombre)), uintptr(unsafe.Pointer(&h)), 0,
	); r == 0 {
		return nil
	}
	defer procClosePrinter.Call(uintptr(h))

	var necesario, devueltos uint32
	procEnumJobsW.Call(uintptr(h), 0, 64, 1, 0, 0,
		uintptr(unsafe.Pointer(&necesario)), uintptr(unsafe.Pointer(&devueltos)))
	if necesario == 0 {
		return nil
	}

	buf := make([]byte, necesario)
	r, _, _ := procEnumJobsW.Call(uintptr(h), 0, 64, 1,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(necesario),
		uintptr(unsafe.Pointer(&necesario)), uintptr(unsafe.Pointer(&devueltos)))
	if r == 0 || devueltos == 0 {
		return nil
	}

	jobs := unsafe.Slice((*jobInfo1)(unsafe.Pointer(&buf[0])), devueltos)
	out := make([]trabajo, 0, devueltos)
	for _, j := range jobs {
		t := trabajo{ID: j.JobID, Paginas: j.TotalPages}
		if j.Document != nil {
			t.Documento = filepath.Base(windows.UTF16PtrToString(j.Document))
		}
		if j.UserName != nil {
			u := windows.UTF16PtrToString(j.UserName)
			if i := strings.LastIndex(u, `\`); i >= 0 {
				u = u[i+1:]
			}
			t.Usuario = u
		}
		out = append(out, t)
	}
	return out
}

func cancelarTrabajo(impresora string, id uint32) error {
	nombre, err := windows.UTF16PtrFromString(impresora)
	if err != nil {
		return err
	}

	var h windows.Handle
	if r, _, e := procOpenPrinterW.Call(
		uintptr(unsafe.Pointer(nombre)), uintptr(unsafe.Pointer(&h)), 0,
	); r == 0 {
		return e
	}
	defer procClosePrinter.Call(uintptr(h))

	if r, _, e := procSetJobW.Call(
		uintptr(h), uintptr(id), 0, 0, uintptr(jobControlDelete),
	); r == 0 {
		return e
	}
	return nil
}
