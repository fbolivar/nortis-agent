//go:build windows

package enforce

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog"
	"golang.org/x/sys/windows/registry"

	"github.com/fbolivar/nortis-agent/internal/contract"
)

// Rutas del registro que gobiernan el almacenamiento extraible.
const (
	claveUSBStor  = `SYSTEM\CurrentControlSet\Services\USBSTOR`
	claveDirectiva = `SYSTEM\CurrentControlSet\Control\StorageDevicePolicies`

	// 3 = el driver arranca con el sistema; 4 = deshabilitado.
	usbstorHabilitado    = 3
	usbstorDeshabilitado = 4
)

// Politicas de navegador para DNS-over-HTTPS.
//
// SIN ESTO EL BLOQUEO WEB NO SIRVE DE NADA. Con DoH activo el navegador resuelve
// los nombres por su cuenta, contra un servidor propio y por HTTPS, saltandose
// por completo el resolvedor del sistema — y con el, el archivo hosts. Se
// comprobo en una maquina real: Edge venia en modo "automatico", que activa DoH
// cuando el proveedor lo soporta.
var politicasDoH = map[string]string{
	"Edge":   `SOFTWARE\Policies\Microsoft\Edge`,
	"Chrome": `SOFTWARE\Policies\Google\Chrome`,
}

// Aplicador impone la politica en el sistema.
type Aplicador struct {
	log zerolog.Logger
	dir string
}

func NuevoAplicador(log zerolog.Logger, dirDatos string) *Aplicador {
	return &Aplicador{log: log.With().Str("modulo", "enforce").Logger(), dir: dirDatos}
}

// Resultado describe que quedo aplicado y que no.
//
// `USB` y `Dominios` dicen lo que EFECTIVAMENTE se impuso, no lo que la politica
// pedia. La diferencia importa: la primera version devolvia el modo solicitado
// aunque la escritura en el registro hubiera fallado, y el resumen anunciaba
// "usb=read_only" sobre un equipo donde no se habia aplicado nada. Es la regla 3
// del paquete incumplida por el propio paquete.
type Resultado struct {
	// USB es el modo aplicado, o "no_aplicado" si no se pudo.
	USB string
	// USBSolicitado es lo que la politica pedia. Difiere de USB cuando fallo.
	USBSolicitado string
	// Dominios es cuantos quedaron bloqueados de verdad. -1 si no se pudo
	// escribir el archivo hosts: distinto de 0, que significa "la politica no
	// pedia bloquear ninguno".
	Dominios   int
	SoloAlerta []string
}

// Cubierto indica si TODO lo que la politica pedia se pudo imponer.
//
// Es lo que deberia mandarse a la consola como estado de cobertura del equipo:
// un panel que muestre "protegido" un equipo donde el registro fallo es peor que
// uno que admita el hueco, porque nadie va a ir a mirar el log.
func (r Resultado) Cubierto() bool {
	return r.USB != "no_aplicado" && r.Dominios >= 0
}

// Aplicar impone la politica. Es idempotente: aplicar dos veces lo mismo no
// cambia nada.
func (a *Aplicador) Aplicar(p *contract.Policy) Resultado {
	estado := CargarEstado(a.dir)
	var res Resultado

	if p == nil {
		// Sin perfil asignado el agente observa pero no interviene. Inventarse
		// una politica —permisiva o restrictiva— seria tomar por el cliente una
		// decision que no tomo.
		a.log.Info().Msg("sin perfil asignado: no se aplica ningun control")
		return res
	}

	res.USB, res.USBSolicitado = a.aplicarUSB(p, estado)

	dominios, soloAlerta := DominiosABloquear(
		p.Web.BlockedDomains, p.Web.AllowedDomains, p.Web.BlockWebmail,
	)
	res.SoloAlerta = soloAlerta
	if a.aplicarWeb(dominios, estado) {
		res.Dominios = len(dominios)
	} else {
		// -1 y no 0: "no se pudo" y "no habia nada que bloquear" son estados
		// distintos y confundirlos oculta un equipo desprotegido.
		res.Dominios = -1
	}

	for _, s := range soloAlerta {
		// No es un fallo, es una limitacion conocida — pero tiene que verse.
		a.log.Warn().Str("control", s).Msg("control no aplicable por esta via; queda solo como alerta")
	}

	estado.Aplicado = true
	if err := estado.Guardar(a.dir); err != nil {
		a.log.Error().Err(err).Msg("no se pudo guardar el estado previo; la reversion podria quedar incompleta")
	}
	return res
}

/* ----------------------------------------------------------------- USB --- */

// aplicarUSB devuelve (aplicado, solicitado). Difieren cuando la escritura en el
// registro falla —tipicamente por falta de privilegios— y en ese caso el equipo
// NO esta cubierto en este canal, por mucho que la politica lo pidiera.
func (a *Aplicador) aplicarUSB(p *contract.Policy, estado *Estado) (string, string) {
	modo := p.USB.Mode
	if modo == "" {
		modo = contract.USBAllow
	}
	solicitado := string(modo)

	// El valor original se anota UNA sola vez, la primera. Releerlo despues
	// guardaria el valor que pusimos nosotros y la reversion no revertiria nada.
	if estado.USBStorStart < 0 {
		if v, ok := leerDword(registry.LOCAL_MACHINE, claveUSBStor, "Start"); ok {
			estado.USBStorStart = int(v)
		}
	}

	switch modo {
	case contract.USBBlock:
		// Con lista blanca NO se deshabilita el driver: si se deshabilita, los
		// dispositivos autorizados tampoco montan. Se deja montar y el
		// recolector expulsa lo que no este en la lista. Es una proteccion algo
		// mas debil —hay una ventana breve en la que el volumen esta montado—
		// pero es la unica forma de que "bloquear salvo estos" signifique algo.
		if len(p.USB.SerialAllowlist) > 0 {
			a.log.Info().Int("autorizados", len(p.USB.SerialAllowlist)).
				Msg("USB: bloqueo con lista blanca; los no autorizados se expulsan al conectarse")
			ok1 := a.escribirUSBStor(usbstorHabilitado)
			ok2 := a.escribirWriteProtect(0, estado)
			return aplicadoO(ok1 && ok2, "block_con_lista_blanca"), solicitado
		}
		ok1 := a.escribirUSBStor(usbstorDeshabilitado)
		ok2 := a.escribirWriteProtect(0, estado)
		return aplicadoO(ok1 && ok2, "block"), solicitado

	case contract.USBReadOnly:
		// Solo lectura corta la SALIDA de informacion sin impedir trabajar con
		// lo que el usuario trae de fuera. Suele ser el punto justo para una
		// PYME: bloquear del todo genera mas friccion de la que el cliente
		// tolera, y acaba con la politica desactivada.
		ok1 := a.escribirUSBStor(usbstorHabilitado)
		ok2 := a.escribirWriteProtect(1, estado)
		return aplicadoO(ok1 && ok2, "read_only"), solicitado

	default:
		ok1 := a.escribirUSBStor(usbstorHabilitado)
		ok2 := a.escribirWriteProtect(0, estado)
		return aplicadoO(ok1 && ok2, "allow"), solicitado
	}
}

// aplicadoO devuelve el modo si de verdad se impuso, y "no_aplicado" si no.
func aplicadoO(ok bool, modo string) string {
	if ok {
		return modo
	}
	return "no_aplicado"
}

func (a *Aplicador) escribirUSBStor(valor uint32) bool {
	if err := escribirDword(registry.LOCAL_MACHINE, claveUSBStor, "Start", valor); err != nil {
		a.log.Error().Err(err).Uint32("valor", valor).
			Msg("no se pudo aplicar la politica de USB; el equipo NO esta cubierto en este canal")
		return false
	}
	return true
}

func (a *Aplicador) escribirWriteProtect(valor uint32, estado *Estado) bool {
	// El valor previo se anota UNA sola vez, igual que USBSTOR\Start. La marca de
	// "ya se leyo" es propia y no se deduce de que el valor existiera: si no
	// existia y se dedujera de ahi, la siguiente pasada leeria el valor que
	// acabamos de escribir nosotros y lo tomaria por el original del cliente.
	if !estado.WriteProtectLeido {
		v, ok := leerDword(registry.LOCAL_MACHINE, claveDirectiva, "WriteProtect")
		AnotarWriteProtect(estado, v, ok)
	}
	if err := escribirDword(registry.LOCAL_MACHINE, claveDirectiva, "WriteProtect", valor); err != nil {
		a.log.Error().Err(err).Msg("no se pudo aplicar el modo solo lectura de USB")
		return false
	}
	return true
}

/* ----------------------------------------------------------------- Web --- */

func (a *Aplicador) aplicarWeb(dominios []string, estado *Estado) bool {
	ruta := rutaHosts()

	actual, err := os.ReadFile(ruta)
	if err != nil {
		a.log.Error().Err(err).Str("archivo", ruta).Msg("no se pudo leer el archivo hosts")
		return false
	}

	nuevo := ComponerHosts(string(actual), dominios)
	if nuevo == string(actual) {
		// Idempotencia: si no cambia nada no se escribe. Reescribir el archivo
		// hosts cada ciclo dispararia las alertas del antivirus del cliente, que
		// vigila justo ese archivo.
		a.aplicarDoH(len(dominios) > 0, estado)
		return true
	}

	// Escritura atomica: se escribe al lado y se renombra. Un corte de corriente
	// a mitad de escritura dejaria el archivo hosts truncado, y con el la
	// resolucion de nombres del equipo rota.
	tmp := ruta + ".nortis.tmp"
	if err := os.WriteFile(tmp, []byte(nuevo), 0o644); err != nil {
		a.log.Error().Err(err).Msg("no se pudo preparar el archivo hosts")
		return false
	}
	if err := os.Rename(tmp, ruta); err != nil {
		_ = os.Remove(tmp)
		a.log.Error().Err(err).Msg("no se pudo aplicar el bloqueo de dominios")
		return false
	}

	a.aplicarDoH(len(dominios) > 0, estado)
	a.vaciarCacheDNS()

	a.log.Info().Int("dominios", len(dominios)).Msg("bloqueo de dominios aplicado")
	return true
}

// aplicarDoH desactiva DNS-over-HTTPS mientras haya dominios bloqueados.
func (a *Aplicador) aplicarDoH(desactivar bool, estado *Estado) {
	for nombre, clave := range politicasDoH {
		if _, ya := estado.DohExistia[nombre]; !ya {
			v, ok := leerCadena(registry.LOCAL_MACHINE, clave, "DnsOverHttpsMode")
			estado.DohExistia[nombre] = ok
			estado.DohOriginal[nombre] = v
		}

		if !desactivar {
			continue
		}

		if err := escribirCadena(registry.LOCAL_MACHINE, clave, "DnsOverHttpsMode", "off"); err != nil {
			a.log.Warn().Err(err).Str("navegador", nombre).
				Msg("no se pudo desactivar DNS-over-HTTPS; el bloqueo de dominios puede saltarse en ese navegador")
		}
	}
}

func (a *Aplicador) vaciarCacheDNS() {
	// Sin esto, un dominio ya resuelto sigue accesible hasta que caduque su
	// entrada en cache: el administrador aplicaria la politica y vería que no
	// surte efecto, sin motivo aparente.
	cmd := exec.Command("ipconfig", "/flushdns")
	if err := cmd.Run(); err != nil {
		a.log.Debug().Err(err).Msg("no se pudo vaciar la cache de DNS")
	}
}

func rutaHosts() string {
	raiz := os.Getenv("SystemRoot")
	if raiz == "" {
		raiz = `C:\Windows`
	}
	return filepath.Join(raiz, "System32", "drivers", "etc", "hosts")
}

/* ----------------------------------------------------------- Reversion --- */

// Revertir deshace todos los cambios y devuelve el equipo a como estaba.
//
// SOLO SE LLAMA AL DESINSTALAR, nunca al detener el servicio. Es deliberado: si
// parar el agente levantara los bloqueos, cualquiera con permiso para detener un
// servicio podria desbloquear el USB en dos clics, y el control no valdria nada.
// El precio es que un agente que muera de forma anomala deja el equipo protegido
// hasta que alguien lo desinstale — que es el lado correcto en el que
// equivocarse para un producto de seguridad.
func (a *Aplicador) Revertir() {
	estado := CargarEstado(a.dir)
	if !estado.Aplicado {
		// Sin estado guardado no se puede restaurar el registro: no se sabe que
		// habia antes, y adivinar es peor que no tocar. Pero el bloque del archivo
		// hosts lleva nuestros marcadores, asi que ese si se puede quitar sin
		// riesgo — y es mejor quitarlo que dejar dominios cortados en un equipo
		// del que ya nadie se hace cargo.
		//
		// Se avisa en vez de salir callando: "no habia nada que revertir" y "no se
		// como estaba el equipo" son cosas distintas, y confundirlas es lo que hace
		// que alguien de por bueno un equipo que sigue bloqueado.
		if a.limpiarHosts() {
			a.log.Warn().Msg("no hay estado guardado: se quito el bloque del archivo hosts, pero las claves de registro hay que revisarlas a mano")
			a.vaciarCacheDNS()
			return
		}
		a.log.Info().Msg("no hay nada que revertir")
		return
	}

	// USB: se restaura el valor original; si no se llego a leer, se deja el
	// valor por defecto de Windows en vez de adivinar.
	original := uint32(usbstorHabilitado)
	if estado.USBStorStart >= 0 {
		original = uint32(estado.USBStorStart)
	}
	if err := escribirDword(registry.LOCAL_MACHINE, claveUSBStor, "Start", original); err != nil {
		a.log.Error().Err(err).Msg("no se pudo restaurar la politica de USB")
	}

	if estado.WriteProtectExistia {
		_ = escribirDword(registry.LOCAL_MACHINE, claveDirectiva, "WriteProtect", estado.WriteProtectOriginal)
	} else {
		_ = borrarValor(registry.LOCAL_MACHINE, claveDirectiva, "WriteProtect")
	}

	a.limpiarHosts()

	// DoH: si el cliente ya tenia una politica propia se restaura tal cual; solo
	// se borra el valor si lo creamos nosotros.
	for nombre, clave := range politicasDoH {
		if estado.DohExistia[nombre] {
			_ = escribirCadena(registry.LOCAL_MACHINE, clave, "DnsOverHttpsMode", estado.DohOriginal[nombre])
		} else {
			_ = borrarValor(registry.LOCAL_MACHINE, clave, "DnsOverHttpsMode")
		}
	}

	a.vaciarCacheDNS()
	_ = os.Remove(rutaEstado(a.dir))
	a.log.Info().Msg("controles revertidos; el equipo queda como estaba antes de instalar el agente")
}

// limpiarHosts quita SOLO el bloque delimitado por nuestros marcadores y
// devuelve si habia algo que quitar. Nada fuera de esos marcadores se toca: el
// archivo hosts es del cliente y puede tener entradas suyas de las que depende
// su red.
func (a *Aplicador) limpiarHosts() bool {
	ruta := rutaHosts()
	actual, err := os.ReadFile(ruta)
	if err != nil {
		return false
	}
	limpio := QuitarBloqueNortis(string(actual))
	if limpio == string(actual) {
		return false
	}
	tmp := ruta + ".nortis.tmp"
	if os.WriteFile(tmp, []byte(limpio), 0o644) != nil {
		return false
	}
	if os.Rename(tmp, ruta) != nil {
		_ = os.Remove(tmp)
		return false
	}
	return true
}

/* -------------------------------------------------------------- Registro --- */

func leerDword(raiz registry.Key, ruta, nombre string) (uint32, bool) {
	k, err := registry.OpenKey(raiz, ruta, registry.QUERY_VALUE)
	if err != nil {
		return 0, false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(nombre)
	if err != nil {
		return 0, false
	}
	return uint32(v), true
}

func escribirDword(raiz registry.Key, ruta, nombre string, valor uint32) error {
	k, _, err := registry.CreateKey(raiz, ruta, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("abriendo %s: %w", ruta, err)
	}
	defer k.Close()
	return k.SetDWordValue(nombre, valor)
}

func leerCadena(raiz registry.Key, ruta, nombre string) (string, bool) {
	k, err := registry.OpenKey(raiz, ruta, registry.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	defer k.Close()
	v, _, err := k.GetStringValue(nombre)
	if err != nil {
		return "", false
	}
	return v, true
}

func escribirCadena(raiz registry.Key, ruta, nombre, valor string) error {
	k, _, err := registry.CreateKey(raiz, ruta, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("abriendo %s: %w", ruta, err)
	}
	defer k.Close()
	return k.SetStringValue(nombre, valor)
}

func borrarValor(raiz registry.Key, ruta, nombre string) error {
	k, err := registry.OpenKey(raiz, ruta, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	err = k.DeleteValue(nombre)
	if err != nil && strings.Contains(err.Error(), "cannot find") {
		return nil
	}
	return err
}
