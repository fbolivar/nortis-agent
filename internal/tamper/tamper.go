package tamper

import (
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ErrNoSoportado lo devuelven las operaciones que solo tienen sentido en
// Windows cuando se compilan en otra plataforma. El agente es un producto solo
// para Windows, pero el paquete compila en Linux para que el nucleo verificable
// —la criptografia del vale— se pruebe en CI sin un runner de Windows.
var ErrNoSoportado = errors.New("la proteccion anti-manipulacion solo esta disponible en Windows")

// ErrSinClaveConsola lo devuelve el endurecimiento cuando no hay una clave
// publica de consola configurada. Es el INTERBLOQUEO DE SEGURIDAD del modelo:
// endurecer sin una via de desbloqueo autorizada construiria justo lo que este
// paquete promete NO construir —un agente irreversible que ni su dueno puede
// quitar— y eso es un rootkit, no un producto de seguridad. Preferimos negarnos
// a endurecer antes que dejar un equipo sin salida.
var ErrSinClaveConsola = errors.New(
	"no hay clave publica de consola configurada: me niego a endurecer sin una via de desbloqueo autorizada")

// consolePublicKeyPEM es la clave publica Ed25519 de la consola, en PEM.
//
// Se fija en tiempo de COMPILACION con -ldflags "-X ...consolePublicKeyPEM=..."
// o se coloca en disco como console_pubkey.pem junto a la configuracion. Es una
// clave PUBLICA: no es secreta y puede versionarse o empotrarse sin riesgo. La
// PRIVADA, con la que la consola firma los vales, jamas vive en el agente.
//
// Va vacia por defecto a proposito: un binario recien clonado no trae ninguna
// autoridad de desbloqueo de nadie, y por el interbloqueo de arriba tampoco se
// deja endurecer hasta que se configure. La ausencia es segura; una clave por
// defecto seria una puerta trasera comun a todas las instalaciones.
var consolePublicKeyPEM string

// ClavePublicaConsola resuelve la clave publica de la consola desde, en orden:
// la variable fijada por ldflags, o el archivo console_pubkey.pem del directorio
// de datos. Devuelve nil si no hay ninguna: la ausencia no es un error aqui, es
// el que llama quien decide si eso le impide seguir.
func ClavePublicaConsola(dirDatos string) (ed25519.PublicKey, error) {
	fuente := consolePublicKeyPEM
	if strings.TrimSpace(fuente) == "" {
		// La ruta es fija bajo el directorio de datos del agente, no una entrada
		// de usuario: se construye en linea para que quede claro —y para que el
		// analizador no la tome por una lectura de ruta arbitraria.
		datos, err := os.ReadFile(filepath.Join(dirDatos, "console_pubkey.pem"))
		if os.IsNotExist(err) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		fuente = string(datos)
	}

	bloque, _ := pem.Decode([]byte(fuente))
	if bloque == nil {
		return nil, errors.New("console_pubkey.pem no contiene un bloque PEM valido")
	}
	// Se acepta tanto una clave "cruda" de 32 bytes en el bloque como una
	// SubjectPublicKeyInfo; para Ed25519, la clave cruda son exactamente 32
	// bytes y es la forma que emite nuestra herramienta.
	if len(bloque.Bytes) == ed25519.PublicKeySize {
		return ed25519.PublicKey(bloque.Bytes), nil
	}
	return nil, errors.New("la clave publica de consola no tiene el tamano de una clave Ed25519")
}

// HayClaveConsola indica si existe una autoridad de desbloqueo configurada. El
// endurecimiento lo consulta para aplicar el interbloqueo de seguridad.
func HayClaveConsola(dirDatos string) bool {
	k, err := ClavePublicaConsola(dirDatos)
	return err == nil && k != nil
}

// Verificar valida un vale contra la clave fijada de la consola. Es el atajo que
// usan el CLI y el servicio; la logica esta en VerificarCon, que es la parte
// probada.
func Verificar(dirDatos, token, endpointID string, ahora time.Time) (*Vale, error) {
	pub, err := ClavePublicaConsola(dirDatos)
	if err != nil {
		return nil, err
	}
	if pub == nil {
		return nil, ErrSinClaveConsola
	}
	return VerificarCon(pub, token, endpointID, ahora)
}

// Estado resume la proteccion vigente, para el subcomando tamper-status y el
// diagnostico de soporte.
type Estado struct {
	// Soportado es false fuera de Windows.
	Soportado bool
	// ServicioEndurecido: el DACL restrictivo esta puesto en el objeto de
	// servicio (el usuario estandar no puede detenerlo ni borrarlo).
	ServicioEndurecido bool
	// DirectorioEndurecido: el DACL restrictivo esta puesto en el directorio de
	// datos (el usuario estandar no puede borrar la cola ni la credencial).
	DirectorioEndurecido bool
	// ClaveConsolaConfigurada: hay autoridad de desbloqueo, luego la
	// desinstalacion autorizada es posible.
	ClaveConsolaConfigurada bool
	// Detalle lleva una explicacion legible cuando algo no esta como se espera.
	Detalle string
}

// nombreSolicitudDesbloqueo es el archivo que deja el administrador (con el
// vale) para que el servicio, que corre como SYSTEM, lo valide y afloje el DACL.
//
// Este rodeo existe porque solo SYSTEM conserva permiso para reescribir el DACL
// del servicio endurecido; el administrador que ejecuta `unlock` no lo tiene, y
// se lo damos precisamente para que un administrador solo, sin vale, no pueda
// aflojar la proteccion por su cuenta. El administrador deja la peticion; SYSTEM
// decide.
const nombreSolicitudDesbloqueo = "unlock.request"

// RutaSolicitudDesbloqueo devuelve la ruta del archivo de peticion de desbloqueo.
func RutaSolicitudDesbloqueo(dirDatos string) string {
	return filepath.Join(dirDatos, nombreSolicitudDesbloqueo)
}

// Endurecer aplica la proteccion completa: DACL restrictivo en el servicio y en
// el directorio de datos. Antes comprueba el INTERBLOQUEO DE SEGURIDAD —negarse
// si no hay autoridad de desbloqueo— para no dejar nunca un equipo irreversible.
//
// Es idempotente: se puede llamar en cada arranque del servicio para reafirmar
// el DACL por si alguien con privilegios lo aflojo a mano.
func Endurecer(nombreServicio, dirDatos string) error {
	if !HayClaveConsola(dirDatos) {
		return ErrSinClaveConsola
	}
	if err := endurecerServicio(nombreServicio); err != nil {
		return err
	}
	return endurecerDirectorio(dirDatos)
}

// Aflojar devuelve al servicio un DACL que permite a los administradores
// detenerlo y borrarlo, para que la desinstalacion pueda proceder. Solo debe
// invocarse tras validar un vale: quien la llama en el servicio es SYSTEM, el
// unico que conserva permiso para reescribir el DACL endurecido.
func Aflojar(nombreServicio string) error {
	return aflojarServicio(nombreServicio)
}

// EstadoActual describe la proteccion vigente sin modificar nada.
func EstadoActual(nombreServicio, dirDatos string) Estado {
	e := Estado{
		Soportado:               soportado,
		ClaveConsolaConfigurada: HayClaveConsola(dirDatos),
	}
	if !soportado {
		e.Detalle = ErrNoSoportado.Error()
		return e
	}
	if s, err := servicioEndurecido(nombreServicio); err == nil {
		e.ServicioEndurecido = s
	} else {
		e.Detalle = "no se pudo leer el DACL del servicio: " + err.Error()
	}
	if d, err := directorioEndurecido(dirDatos); err == nil {
		e.DirectorioEndurecido = d
	} else if e.Detalle == "" {
		e.Detalle = "no se pudo leer el DACL del directorio: " + err.Error()
	}
	return e
}
