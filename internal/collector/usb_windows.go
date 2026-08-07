//go:build windows

package collector

import (
	"context"
	"strings"
	"time"
	"unsafe"

	"github.com/rs/zerolog"
	"golang.org/x/sys/windows"

	"github.com/fbolivar/nortis-agent/internal/contract"
)

// IntervaloUSB es cada cuanto se sondean las unidades extraibles.
//
// Se sondea en vez de escuchar WM_DEVICECHANGE porque el mensaje exige una
// ventana y un bucle de mensajes dentro de un servicio, y a cambio no aporta
// nada: una memoria USB no se conecta y desconecta en menos de tres segundos, y
// si lo hiciera no habria dado tiempo a copiar nada. La simplicidad aqui vale
// mas que la inmediatez.
const IntervaloUSB = 3 * time.Second

// USBCollector detecta la conexion de unidades extraibles.
//
// Es el canal de fuga numero uno en una PYME y la unica regla del motor DLP con
// severidad CRITICA. Por eso no depende de la politica para observar: registra
// siempre, aunque el modo sea `allow`. Saber que alguien conecto una memoria un
// viernes a las siete es informacion aunque en ese momento estuviera permitido.
type USBCollector struct {
	log      zerolog.Logger
	maquina  *maquinaUSB
	// modo devuelve el modo de enforcement vigente para poder informarlo. Puede
	// ser nil, en cuyo caso se reporta "allow".
	modo func() string
}

func NewUSBCollector(log zerolog.Logger, modo func() string) *USBCollector {
	return &USBCollector{
		log:     log.With().Str("recolector", "usb").Logger(),
		maquina: nuevaMaquinaUSB(),
		modo:    modo,
	}
}

func (c *USBCollector) Name() string { return "usb" }

func (c *USBCollector) Run(ctx context.Context, emit Emit) {
	// El primer sondeo solo toma estado: las memorias YA conectadas al arrancar
	// el servicio no son un evento de conexion. Emitirlas produciria un incidente
	// critico cada vez que el equipo se reinicia con un disco externo puesto, y
	// nada erosiona mas rapido la confianza en una alerta que verla salir sola.
	c.maquina.observar(c.sondear(), c.enforcement(), time.Now().UTC())
	c.log.Debug().Msg("estado inicial de unidades extraibles registrado")

	t := time.NewTicker(IntervaloUSB)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, e := range c.maquina.observar(c.sondear(), c.enforcement(), time.Now().UTC()) {
				c.log.Info().
					Str("serial", stringDe(e.Payload["serial"])).
					Str("etiqueta", stringDe(e.Payload["label"])).
					Msg("unidad extraible conectada")
				emit(e)
			}
		}
	}
}

func (c *USBCollector) enforcement() string {
	if c.modo == nil {
		return string(contract.USBAllow)
	}
	if m := c.modo(); m != "" {
		return m
	}
	return string(contract.USBAllow)
}

func stringDe(v any) string {
	s, _ := v.(string)
	return s
}

// usuarioDeSesionActiva devuelve quien esta usando el equipo.
//
// NO se usa os/user: el agente corre como servicio bajo LocalSystem, asi que
// preguntar por el usuario del proceso devuelve SYSTEM. Cada incidente de USB
// quedaria atribuido a la cuenta de servicio en vez de a la persona, que es
// justo el dato por el que se abre el incidente.
//
// Se prefiere la sesion de consola —quien esta fisicamente delante— y se cae a
// la primera sesion activa que haya, que cubre el acceso remoto.
func usuarioDeSesionActiva() string {
	sesiones, err := enumerarSesiones()
	if err != nil {
		return ""
	}

	for _, s := range sesiones {
		if s.Estado == wtsActive && !s.Bloqueada {
			return s.Usuario
		}
	}
	// Con la pantalla bloqueada sigue habiendo un usuario con sesion abierta, y
	// conectar una memoria con el equipo bloqueado es precisamente algo que
	// interesa registrar.
	for _, s := range sesiones {
		if s.Usuario != "" {
			return s.Usuario
		}
	}
	return ""
}

/* ------------------------------------------------------ Sondeo del sistema --- */

func (c *USBCollector) sondear() []volumen {
	mascara, err := windows.GetLogicalDrives()
	if err != nil {
		c.log.Debug().Err(err).Msg("no se pudieron enumerar las unidades")
		return nil
	}

	usuario := usuarioDeSesionActiva()

	var out []volumen
	for i := uint(0); i < 26; i++ {
		if mascara&(1<<i) == 0 {
			continue
		}

		letra := string(rune('A'+i)) + ":"
		raiz := letra + `\`

		raizPtr, err := windows.UTF16PtrFromString(raiz)
		if err != nil {
			continue
		}

		// Solo extraibles. DRIVE_FIXED incluiria el disco del sistema, y vigilar
		// C: como si fuera una memoria USB llenaria la consola de ruido.
		if windows.GetDriveType(raizPtr) != windows.DRIVE_REMOVABLE {
			continue
		}

		v := volumen{Letra: letra, Usuario: usuario}
		v.Etiqueta, v.SerialVolumen = infoVolumen(raiz)
		v.CapacidadByte = capacidad(raiz)
		v.Serial = serialDeDispositivo(letra)

		out = append(out, v)
	}
	return out
}

// infoVolumen devuelve la etiqueta y el serial del SISTEMA DE ARCHIVOS.
func infoVolumen(raiz string) (etiqueta, serialVolumen string) {
	raizPtr, err := windows.UTF16PtrFromString(raiz)
	if err != nil {
		return "", ""
	}

	nombre := make([]uint16, 261)
	sistema := make([]uint16, 261)
	var numeroSerie, maxComponente, banderas uint32

	err = windows.GetVolumeInformation(
		raizPtr,
		&nombre[0], uint32(len(nombre)),
		&numeroSerie, &maxComponente, &banderas,
		&sistema[0], uint32(len(sistema)),
	)
	if err != nil {
		// Ocurre con un lector de tarjetas vacio: la unidad existe pero no hay
		// medio. No es un fallo que reportar, es una unidad sin nada dentro.
		return "", ""
	}

	etiqueta = windows.UTF16ToString(nombre)
	if numeroSerie != 0 {
		const hex = "0123456789ABCDEF"
		b := make([]byte, 8)
		for i := 0; i < 8; i++ {
			b[7-i] = hex[(numeroSerie>>(4*i))&0xF]
		}
		serialVolumen = string(b)
	}
	return etiqueta, serialVolumen
}

func capacidad(raiz string) uint64 {
	raizPtr, err := windows.UTF16PtrFromString(raiz)
	if err != nil {
		return 0
	}
	var libresUsuario, total, libres uint64
	if err := windows.GetDiskFreeSpaceEx(raizPtr, &libresUsuario, &total, &libres); err != nil {
		return 0
	}
	return total
}

/* --------------------------------------- Serial de dispositivo (IOCTL) --- */

// Constantes de IOCTL_STORAGE_QUERY_PROPERTY. No estan en x/sys/windows.
const (
	ioctlStorageQueryProperty = 0x2D1400
	storageDeviceProperty     = 0
	propertyStandardQuery     = 0
)

type storagePropertyQuery struct {
	PropertyId uint32
	QueryType  uint32
	AdditionalParameters [1]byte
}

// storageDeviceDescriptor es la cabecera del descriptor. Los textos (serial,
// fabricante, modelo) van DETRAS de la estructura y se localizan por
// desplazamiento en bytes desde su inicio, que es por lo que hace falta leer el
// bufer crudo en vez de mapearlo a un struct completo.
type storageDeviceDescriptor struct {
	Version               uint32
	Size                  uint32
	DeviceType            byte
	DeviceTypeModifier    byte
	RemovableMedia        byte
	CommandQueueing       byte
	VendorIdOffset        uint32
	ProductIdOffset       uint32
	ProductRevisionOffset uint32
	SerialNumberOffset    uint32
	BusType               uint32
	RawPropertiesLength   uint32
}

// serialDeDispositivo lee el serial de hardware de la unidad.
//
// POR QUE NO BASTA EL SERIAL DEL VOLUMEN: el del volumen lo asigna el formateo,
// asi que cualquiera puede cambiarlo con un clic derecho. Una lista blanca
// construida sobre el se sortea formateando la memoria, que es exactamente lo
// que haria alguien decidido a sacar informacion. El de dispositivo va grabado
// por el fabricante y sobrevive.
//
// Devuelve "" cuando el dispositivo no lo expone —ocurre con lectores de
// tarjetas y adaptadores baratos—; el llamador cae entonces al del volumen,
// marcado como tal.
func serialDeDispositivo(letra string) string {
	ruta, err := windows.UTF16PtrFromString(`\\.\` + letra)
	if err != nil {
		return ""
	}

	// Sin GENERIC_READ: consultar propiedades no necesita leer datos, y pedir
	// lectura sobre un volumen extraible puede fallar por permisos o hacer girar
	// un disco dormido sin motivo.
	h, err := windows.CreateFile(
		ruta, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING, 0, 0,
	)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)

	consulta := storagePropertyQuery{
		PropertyId: storageDeviceProperty,
		QueryType:  propertyStandardQuery,
	}

	buf := make([]byte, 1024)
	var devueltos uint32

	err = windows.DeviceIoControl(
		h, ioctlStorageQueryProperty,
		(*byte)(unsafe.Pointer(&consulta)), uint32(unsafe.Sizeof(consulta)),
		&buf[0], uint32(len(buf)),
		&devueltos, nil,
	)
	if err != nil || devueltos < uint32(unsafe.Sizeof(storageDeviceDescriptor{})) {
		return ""
	}

	desc := (*storageDeviceDescriptor)(unsafe.Pointer(&buf[0]))
	off := desc.SerialNumberOffset

	// Offset 0 significa "este dispositivo no reporta serial". Y se comprueba
	// contra los bytes REALMENTE devueltos: un descriptor con un offset mayor
	// que la respuesta leeria memoria fuera del bufer.
	if off == 0 || off >= devueltos {
		return ""
	}

	fin := off
	for fin < devueltos && buf[fin] != 0 {
		fin++
	}

	return strings.TrimSpace(string(buf[off:fin]))
}
