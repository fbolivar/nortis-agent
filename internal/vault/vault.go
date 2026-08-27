// Package vault cifra y descifra una carpeta en un contenedor protegido con
// contrasena, portable (un solo archivo .nrtv). Es el equivalente a EasyLock /
// Endpoint Protector: el usuario se lleva la informacion en un USB pero cifrada,
// y solo la abre quien tiene la clave.
//
// CRIPTOGRAFIA (solo stdlib, sin dependencias):
//   - Derivacion de clave: PBKDF2-HMAC-SHA256 (crypto/pbkdf2, Go 1.24+), 600k
//     iteraciones sobre un salt aleatorio de 16 bytes.
//   - Cifrado: AES-256-GCM por bloques de 64 KiB. El nonce es un prefijo
//     aleatorio de 4 bytes (fijo por contenedor) + un contador de 8 bytes que
//     avanza por bloque, asi que nunca se repite. El AAD de cada bloque lleva el
//     contador y un bit de "ultimo bloque": reordenar, duplicar o TRUNCAR el
//     contenedor rompe la autenticacion. Una contrasena incorrecta falla en el
//     primer bloque.
//   - El contenido en claro es un tar de la carpeta, de modo que se preserva la
//     estructura y los nombres.
package vault

import (
	"archive/tar"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	magic     = "NRTVAULT1" // 9 bytes
	version   = 1
	saltLen   = 16
	prefixLen = 4
	iters     = 600_000
	keyLen    = 32
	chunkSize = 64 * 1024
)

var (
	// ErrPassword se devuelve cuando la contrasena es incorrecta o el contenedor
	// esta dañado/manipulado (no se distingue a proposito: dar detalle ayudaria a
	// un atacante).
	ErrPassword = errors.New("contrasena incorrecta o contenedor dañado")
	errFormato  = errors.New("no es un contenedor Nortis valido")
)

func derivarClave(password string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, password, salt, iters, keyLen)
}

func nonce(prefix []byte, contador uint64) []byte {
	n := make([]byte, 12)
	copy(n, prefix)
	binary.BigEndian.PutUint64(n[prefixLen:], contador)
	return n
}

func aad(contador uint64, ultimo bool) []byte {
	a := make([]byte, 9)
	binary.BigEndian.PutUint64(a[:8], contador)
	if ultimo {
		a[8] = 1
	}
	return a
}

// Sellar comprime la carpeta `origen` y la escribe cifrada en `contenedor`.
func Sellar(origen, contenedor, password string) error {
	if password == "" {
		return errors.New("la contrasena no puede estar vacia")
	}
	info, err := os.Stat(origen)
	if err != nil {
		return fmt.Errorf("no se pudo leer el origen: %w", err)
	}

	salt := make([]byte, saltLen)
	prefix := make([]byte, prefixLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	if _, err := rand.Read(prefix); err != nil {
		return err
	}
	clave, err := derivarClave(password, salt)
	if err != nil {
		return err
	}
	gcm, err := nuevoGCM(clave)
	if err != nil {
		return err
	}

	out, err := os.Create(contenedor) // #nosec G304 -- el contenedor es una ruta que el usuario elige en la CLI de esta herramienta portable
	if err != nil {
		return fmt.Errorf("no se pudo crear el contenedor: %w", err)
	}
	defer func() { _ = out.Close() }()

	// Cabecera: magic | version | iters | salt | prefijo de nonce.
	cab := make([]byte, 0, len(magic)+1+4+saltLen+prefixLen)
	cab = append(cab, magic...)
	cab = append(cab, version)
	cab = binary.BigEndian.AppendUint32(cab, iters)
	cab = append(cab, salt...)
	cab = append(cab, prefix...)
	if _, err := out.Write(cab); err != nil {
		return err
	}

	// El contenido en claro es un tar de la carpeta, que se lee por bloques desde
	// una tuberia mientras una goroutine lo va generando.
	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(escribirTar(pw, origen, info))
	}()

	buf := make([]byte, chunkSize)
	var contador uint64
	// pend guarda el bloque anterior para poder marcar el ULTIMO al llegar al EOF.
	var pend []byte
	escribirBloque := func(plano []byte, ultimo bool) error {
		ct := gcm.Seal(nil, nonce(prefix, contador), plano, aad(contador, ultimo))
		var lp [4]byte
		binary.BigEndian.PutUint32(lp[:], uint32(len(ct)))
		if _, err := out.Write(lp[:]); err != nil {
			return err
		}
		_, err := out.Write(ct)
		contador++
		return err
	}
	for {
		n, rerr := io.ReadFull(pr, buf)
		if n > 0 {
			if pend != nil {
				if err := escribirBloque(pend, false); err != nil {
					return err
				}
			}
			pend = append([]byte(nil), buf[:n]...)
		}
		if errors.Is(rerr, io.EOF) || errors.Is(rerr, io.ErrUnexpectedEOF) {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	if pend == nil {
		pend = []byte{} // carpeta vacia: aun asi hay un bloque final (el pie del tar)
	}
	if err := escribirBloque(pend, true); err != nil {
		return err
	}
	return out.Close()
}

// Abrir descifra `contenedor` y extrae su contenido en la carpeta `destino`.
func Abrir(contenedor, destino, password string) error {
	if password == "" {
		return errors.New("la contrasena no puede estar vacia")
	}
	in, err := os.Open(contenedor) // #nosec G304 -- el contenedor es una ruta que el usuario elige en la CLI de esta herramienta portable
	if err != nil {
		return fmt.Errorf("no se pudo abrir el contenedor: %w", err)
	}
	defer func() { _ = in.Close() }()

	cab := make([]byte, len(magic)+1+4+saltLen+prefixLen)
	if _, err := io.ReadFull(in, cab); err != nil {
		return errFormato
	}
	if string(cab[:len(magic)]) != magic || cab[len(magic)] != version {
		return errFormato
	}
	off := len(magic) + 1
	off += 4 // iters (fijo)
	salt := cab[off : off+saltLen]
	off += saltLen
	prefix := cab[off : off+prefixLen]

	clave, err := derivarClave(password, salt)
	if err != nil {
		return err
	}
	gcm, err := nuevoGCM(clave)
	if err != nil {
		return err
	}

	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(extraerTar(pr, destino))
	}()

	leerBloque := func() ([]byte, error) {
		var lp [4]byte
		if _, err := io.ReadFull(in, lp[:]); err != nil {
			return nil, err // io.EOF marca el fin de los bloques
		}
		n := binary.BigEndian.Uint32(lp[:])
		if n == 0 || n > chunkSize+64 {
			return nil, errFormato
		}
		ct := make([]byte, n)
		if _, err := io.ReadFull(in, ct); err != nil {
			return nil, errFormato
		}
		return ct, nil
	}

	var contador uint64
	descifrar := func(ct []byte, ultimo bool) error {
		plano, err := gcm.Open(nil, nonce(prefix, contador), ct, aad(contador, ultimo))
		if err != nil {
			return ErrPassword
		}
		contador++
		_, werr := pw.Write(plano)
		return werr
	}

	// Se lee con un bloque de adelanto para saber cual es el ULTIMO (el que va
	// justo antes del EOF): ese lleva el bit de final en su AAD.
	cur, err := leerBloque()
	if err != nil {
		_ = pw.CloseWithError(errFormato)
		return errFormato
	}
	for {
		next, err := leerBloque()
		if errors.Is(err, io.EOF) {
			if derr := descifrar(cur, true); derr != nil {
				_ = pw.CloseWithError(derr)
				return derr
			}
			break
		}
		if err != nil {
			_ = pw.CloseWithError(err)
			return err
		}
		if derr := descifrar(cur, false); derr != nil {
			_ = pw.CloseWithError(derr)
			return derr
		}
		cur = next
	}
	return pw.Close()
}

func nuevoGCM(clave []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(clave)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// escribirTar mete la carpeta (o archivo) `origen` en un tar sobre `w`.
func escribirTar(w io.Writer, origen string, info os.FileInfo) error {
	tw := tar.NewWriter(w)
	defer func() { _ = tw.Close() }()

	base := filepath.Dir(origen)
	if info.IsDir() {
		base = origen
	}

	return filepath.Walk(origen, func(ruta string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(base, ruta)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		hdr, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if fi.IsDir() || !fi.Mode().IsRegular() {
			return nil
		}
		f, err := os.Open(ruta) // #nosec G304 -- ruta la produce el recorrido de la carpeta elegida por el usuario, no una entrada remota
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		_, err = io.Copy(tw, f)
		return err
	})
}

// extraerTar vuelca el tar de `r` en `destino`, rechazando rutas peligrosas.
func extraerTar(r io.Reader, destino string) error {
	if err := os.MkdirAll(destino, 0o750); err != nil {
		return err
	}
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		nombre := filepath.Clean(hdr.Name)
		if nombre == "." || strings.HasPrefix(nombre, "..") || filepath.IsAbs(nombre) ||
			strings.Contains(nombre, ".."+string(filepath.Separator)) {
			return fmt.Errorf("entrada peligrosa en el contenedor: %q", hdr.Name)
		}
		destPath := filepath.Join(destino, nombre)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(destPath, 0o750); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(destPath), 0o750); err != nil {
				return err
			}
			f, err := os.OpenFile(destPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // #nosec G304 -- destPath validado contra traversal arriba
			if err != nil {
				return err
			}
			_, cerr := io.Copy(f, tr) // #nosec G110 -- el contenido ya esta autenticado por GCM antes de descomprimirse, no es una fuente no confiable
			if cerr != nil {
				_ = f.Close()
				return cerr
			}
			if err := f.Close(); err != nil {
				return err
			}
		}
	}
}
