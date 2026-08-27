// Command nortis-vault es una herramienta PORTABLE para cifrar y descifrar una
// carpeta en un contenedor protegido con contrasena (.nrtv). Es el equivalente a
// EasyLock: el usuario copia la herramienta y su contenedor a un USB, y solo abre
// la informacion quien tiene la clave. Un solo ejecutable, sin instalacion.
//
// Uso:
//
//	nortis-vault                              menu interactivo
//	nortis-vault sellar  <carpeta> <archivo.nrtv>
//	nortis-vault abrir   <archivo.nrtv> <carpeta-destino>
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/fbolivar/nortis-agent/internal/vault"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		if err := interactivo(); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}
		return
	}

	switch args[0] {
	case "sellar", "seal", "cifrar":
		if len(args) != 3 {
			uso()
		}
		if err := sellar(args[1], args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}
	case "abrir", "open", "descifrar":
		if len(args) != 3 {
			uso()
		}
		if err := abrir(args[1], args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}
	default:
		uso()
	}
}

func uso() {
	fmt.Fprintln(os.Stderr, "Uso:")
	fmt.Fprintln(os.Stderr, "  nortis-vault sellar <carpeta> <archivo.nrtv>")
	fmt.Fprintln(os.Stderr, "  nortis-vault abrir  <archivo.nrtv> <carpeta-destino>")
	fmt.Fprintln(os.Stderr, "  nortis-vault           (menu interactivo)")
	os.Exit(2)
}

func sellar(origen, contenedor string) error {
	p1, err := vault.LeerPassword("Contrasena para el contenedor: ")
	if err != nil {
		return err
	}
	p2, err := vault.LeerPassword("Repite la contrasena: ")
	if err != nil {
		return err
	}
	if p1 != p2 {
		return fmt.Errorf("las contrasenas no coinciden")
	}
	if len(p1) < 8 {
		return fmt.Errorf("usa una contrasena de al menos 8 caracteres")
	}
	fmt.Println("Cifrando…")
	if err := vault.Sellar(origen, contenedor, p1); err != nil {
		return err
	}
	fmt.Printf("Listo: %s cifrado en %s\n", origen, contenedor)
	fmt.Println("Guarda bien la contrasena: sin ella el contenido NO se puede recuperar.")
	return nil
}

func abrir(contenedor, destino string) error {
	p, err := vault.LeerPassword("Contrasena del contenedor: ")
	if err != nil {
		return err
	}
	fmt.Println("Descifrando…")
	if err := vault.Abrir(contenedor, destino, p); err != nil {
		return err
	}
	fmt.Printf("Listo: %s abierto en %s\n", contenedor, destino)
	return nil
}

func interactivo() error {
	r := bufio.NewReader(os.Stdin)
	fmt.Println("Nortis Vault — cifrado portable de carpetas")
	fmt.Println("  1) Cifrar una carpeta en un contenedor")
	fmt.Println("  2) Abrir un contenedor")
	fmt.Print("Elige (1/2): ")
	op, _ := r.ReadString('\n')
	switch strings.TrimSpace(op) {
	case "1":
		origen := pedir(r, "Carpeta a cifrar: ")
		contenedor := pedir(r, "Archivo de salida (.nrtv): ")
		if !strings.HasSuffix(strings.ToLower(contenedor), ".nrtv") {
			contenedor += ".nrtv"
		}
		return sellar(origen, contenedor)
	case "2":
		contenedor := pedir(r, "Contenedor (.nrtv): ")
		destino := pedir(r, "Carpeta destino: ")
		return abrir(contenedor, destino)
	default:
		return fmt.Errorf("opcion no valida")
	}
}

func pedir(r *bufio.Reader, prompt string) string {
	fmt.Print(prompt)
	s, _ := r.ReadString('\n')
	return strings.Trim(strings.TrimSpace(s), `"`)
}
