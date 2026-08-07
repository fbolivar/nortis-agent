//go:build windows

package collector

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Codigos de control para desmontar y expulsar un volumen. No estan en
// x/sys/windows y se calculan con la macro CTL_CODE de Windows.
const (
	fsctlLockVolume            = 0x00090018
	fsctlDismountVolume        = 0x00090020
	ioctlStorageMediaRemoval   = 0x002D4804
	ioctlStorageEjectMedia     = 0x002D4808
)

// preventMediaRemoval es el parametro de IOCTL_STORAGE_MEDIA_REMOVAL.
type preventMediaRemoval struct {
	PreventMediaRemoval byte
}

// Expulsar desmonta y expulsa una unidad extraible.
//
// ES LA SEGUNDA MITAD DEL MODO "BLOQUEAR SALVO ESTOS". Con lista blanca no se
// puede deshabilitar el driver de almacenamiento —los dispositivos autorizados
// tampoco montarian—, asi que se deja montar todo y se expulsa lo que no esta
// autorizado. Sin esta funcion, ese modo dejaba el driver activo y no bloqueaba
// absolutamente nada.
//
// LA SECUENCIA IMPORTA Y NO ES OPCIONAL. Expulsar directamente falla mientras el
// sistema de archivos siga montado, asi que hay que:
//
//  1. LOCK_VOLUME     — pedir el volumen en exclusiva. Falla si alguna
//     aplicacion tiene un archivo abierto ahi, que es
//     precisamente cuando NO conviene arrancarlo de golpe.
//  2. DISMOUNT_VOLUME — desmontar el sistema de archivos.
//  3. MEDIA_REMOVAL   — levantar el bloqueo de expulsion por software.
//  4. EJECT_MEDIA     — expulsar.
//
// Saltarse el paso 1 y forzar el desmontaje corromperia datos que el usuario
// estuviera escribiendo. Si el volumen esta ocupado se prefiere fallar y
// registrarlo: un agente que corrompe archivos del cliente causa mas daño que la
// fuga que intenta evitar.
func Expulsar(letra string) error {
	letra = strings.TrimSuffix(strings.ToUpper(strings.TrimSpace(letra)), `\`)
	if len(letra) != 2 || letra[1] != ':' {
		return fmt.Errorf("letra de unidad invalida: %q", letra)
	}

	ruta, err := windows.UTF16PtrFromString(`\\.\` + letra)
	if err != nil {
		return err
	}

	// Se exige lectura Y escritura: desmontar modifica el estado del volumen.
	// FILE_SHARE_* amplio para no fallar solo porque otra aplicacion lo tenga
	// abierto — de eso ya se encarga el bloqueo del paso 1.
	h, err := windows.CreateFile(
		ruta,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING, 0, 0,
	)
	if err != nil {
		return fmt.Errorf("abriendo %s: %w", letra, err)
	}
	defer windows.CloseHandle(h)

	var devueltos uint32

	if err := windows.DeviceIoControl(h, fsctlLockVolume, nil, 0, nil, 0, &devueltos, nil); err != nil {
		// Volumen ocupado. Se informa y NO se fuerza: forzar el desmontaje con
		// escrituras en vuelo corrompe los archivos del usuario.
		return fmt.Errorf("el volumen %s esta en uso y no se puede expulsar sin arriesgar datos: %w", letra, err)
	}

	if err := windows.DeviceIoControl(h, fsctlDismountVolume, nil, 0, nil, 0, &devueltos, nil); err != nil {
		return fmt.Errorf("desmontando %s: %w", letra, err)
	}

	// Permitir la expulsion por software. Algunos dispositivos la bloquean
	// mientras creen que estan en uso.
	permitir := preventMediaRemoval{PreventMediaRemoval: 0}
	_ = windows.DeviceIoControl(
		h, ioctlStorageMediaRemoval,
		(*byte)(unsafe.Pointer(&permitir)), uint32(unsafe.Sizeof(permitir)),
		nil, 0, &devueltos, nil,
	)

	if err := windows.DeviceIoControl(h, ioctlStorageEjectMedia, nil, 0, nil, 0, &devueltos, nil); err != nil {
		// Hay dispositivos —sobre todo discos externos con alimentacion propia—
		// que no admiten expulsion por software. El desmontaje del paso 2 ya
		// dejo el volumen inaccesible, que es el efecto que importa: el usuario
		// no puede copiar nada ahi.
		return fmt.Errorf("desmontado pero no expulsado (%s): %w", letra, err)
	}

	return nil
}

// AutorizadoEnListaBlanca indica si un serial esta permitido.
//
// La comparacion ignora mayusculas y espacios porque el serial se transcribe a
// mano desde una etiqueta o desde el panel: exigir coincidencia exacta haria que
// una lista blanca correcta no funcionara por un espacio al final, y el
// administrador no tendria forma de verlo.
func AutorizadoEnListaBlanca(serial string, listaBlanca []string) bool {
	s := strings.ToUpper(strings.TrimSpace(serial))
	if s == "" {
		// Un dispositivo que no expone serial NO puede estar autorizado: si se
		// permitiera, bastaria con usar una memoria sin serial para saltarse la
		// lista blanca entera.
		return false
	}
	for _, a := range listaBlanca {
		if strings.ToUpper(strings.TrimSpace(a)) == s {
			return true
		}
	}
	return false
}
