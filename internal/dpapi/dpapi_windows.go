//go:build windows

// Package dpapi cifra secretos en disco con la Data Protection API de Windows.
//
// Sirve para una sola cosa: que la API key del tenant no quede en texto plano en
// el disco del endpoint. Esa credencial da acceso de escritura a la telemetria
// de toda la organizacion, asi que un archivo legible por cualquier proceso con
// acceso al sistema de archivos seria regalarla.
package dpapi

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	crypt32            = windows.NewLazySystemDLL("crypt32.dll")
	kernel32           = windows.NewLazySystemDLL("kernel32.dll")
	procCryptProtect   = crypt32.NewProc("CryptProtectData")
	procCryptUnprotect = crypt32.NewProc("CryptUnprotectData")
	procLocalFree      = kernel32.NewProc("LocalFree")
)

// CRYPTPROTECT_LOCAL_MACHINE: la clave de cifrado se ata a la MAQUINA y no a la
// cuenta de usuario.
//
// Es una concesion consciente. Sin este flag, solo la cuenta que cifro puede
// descifrar — pero el enrolamiento lo ejecuta un administrador y el servicio
// corre como LocalSystem, asi que el servicio no podria leer su propia
// credencial. La contrapartida es que cualquier proceso de la maquina que logre
// ejecutarse podria descifrarla; se compensa con los permisos NTFS del archivo,
// que solo conceden acceso a SYSTEM y a Administradores.
const cryptprotectLocalMachine = 0x4

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newBlob(d []byte) dataBlob {
	if len(d) == 0 {
		return dataBlob{}
	}
	return dataBlob{cbData: uint32(len(d)), pbData: &d[0]}
}

func (b dataBlob) bytes() []byte {
	if b.pbData == nil || b.cbData == 0 {
		return nil
	}
	// Se copia antes de liberar la memoria que reservo Windows: devolver una
	// vista sobre memoria ya liberada seria un uso despues de liberar.
	out := make([]byte, b.cbData)
	copy(out, unsafe.Slice(b.pbData, b.cbData))
	return out
}

func (b dataBlob) free() {
	if b.pbData != nil {
		_, _, _ = procLocalFree.Call(uintptr(unsafe.Pointer(b.pbData)))
	}
}

// Protect cifra un secreto para esta maquina.
func Protect(plaintext []byte) ([]byte, error) {
	in := newBlob(plaintext)
	var out dataBlob

	// El descriptor (2do parametro) va nulo: es solo una etiqueta legible que se
	// almacena junto al blob, y aqui solo serviria para revelar que contiene.
	r, _, err := procCryptProtect.Call(
		uintptr(unsafe.Pointer(&in)),
		0, 0, 0, 0,
		cryptprotectLocalMachine,
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptProtectData: %w", err)
	}
	defer out.free()

	return out.bytes(), nil
}

// Unprotect descifra un secreto protegido en ESTA maquina.
//
// Si el disco se clona a otro equipo, esto falla — y es el comportamiento
// deseado: la credencial no debe seguir siendo valida en una maquina distinta de
// aquella en la que se instalo el agente.
func Unprotect(ciphertext []byte) ([]byte, error) {
	in := newBlob(ciphertext)
	var out dataBlob

	r, _, err := procCryptUnprotect.Call(
		uintptr(unsafe.Pointer(&in)),
		0, 0, 0, 0,
		cryptprotectLocalMachine,
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptUnprotectData: %w", err)
	}
	defer out.free()

	return out.bytes(), nil
}
