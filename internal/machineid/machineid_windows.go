//go:build windows

// Package machineid deriva la identidad estable del equipo.
package machineid

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	osuser "os/user"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Fingerprint devuelve la huella de maquina que identifica al endpoint ante la
// consola.
//
// Se deriva del MachineGuid del registro, que Windows genera en la instalacion y
// sobrevive a reinicios, cambios de nombre y actualizaciones. Es lo que permite
// que reinstalar el agente ACTUALICE el equipo en el inventario en vez de
// duplicarlo — y como la facturacion va por equipo, un duplicado le cuesta
// dinero al cliente.
//
// Se devuelve HASHEADO, no en crudo: el MachineGuid es un identificador de
// sistema que no hace falta exponer en una base de datos ajena, y el hash sirve
// igual de bien para comparar.
func Fingerprint() (string, error) {
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Cryptography`,
		registry.QUERY_VALUE|registry.WOW64_64KEY, // 64KEY: un agente de 32 bits leeria una vista redirigida
	)
	if err != nil {
		return "", fmt.Errorf("abriendo el registro: %w", err)
	}
	defer key.Close()

	guid, _, err := key.GetStringValue("MachineGuid")
	if err != nil {
		return "", fmt.Errorf("leyendo MachineGuid: %w", err)
	}

	sum := sha256.Sum256([]byte("nortis-agent:" + strings.TrimSpace(guid)))
	return hex.EncodeToString(sum[:]), nil
}

// Hostname devuelve el nombre del equipo.
func Hostname() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "desconocido"
}

// OSVersion devuelve una descripcion legible de la version de Windows.
func OSVersion() string {
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`,
		registry.QUERY_VALUE|registry.WOW64_64KEY,
	)
	if err != nil {
		return "Windows"
	}
	defer key.Close()

	product, _, _ := key.GetStringValue("ProductName")
	display, _, _ := key.GetStringValue("DisplayVersion")

	// ProductName sigue diciendo "Windows 10" en Windows 11 por compatibilidad;
	// el numero de build es lo unico fiable para distinguirlos.
	if v := windows.RtlGetVersion(); v != nil && v.BuildNumber >= 22000 {
		product = strings.Replace(product, "Windows 10", "Windows 11", 1)
	}

	out := strings.TrimSpace(product)
	if out == "" {
		out = "Windows"
	}
	if display != "" {
		out += " " + display
	}
	return out
}

// CurrentUser devuelve el usuario con sesion iniciada, sin el dominio.
//
// Es un dato operativo para el analista, no una identidad de Nortis: sirve para
// saber quien estaba usando el equipo cuando ocurrio algo.
func CurrentUser() string {
	u, err := osuser.Current()
	if err != nil || u == nil {
		return ""
	}

	// os/user devuelve DOMINIO\usuario en Windows. Se recorta el dominio: al
	// analista le sirve el nombre de la persona, y el dominio es ruido que
	// ademas revela la estructura interna del cliente.
	name := u.Username
	if i := strings.LastIndex(name, `\`); i >= 0 {
		name = name[i+1:]
	}
	return name
}
