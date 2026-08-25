// Herramienta de operaciones para la desinstalacion autorizada.
//
// NO forma parte del binario del servicio ni se despliega en los equipos. Su
// unico cometido es, mientras la consola aun no emite vales, poder:
//
//	keygen                 generar el par de claves de la autoridad de desbloqueo
//	sign  -endpoint <id>   firmar un vale de desinstalacion para un equipo
//
// La clave PRIVADA vive aqui, en manos de operaciones, y jamas en el agente. El
// agente solo lleva la PUBLICA (console_pubkey.pem), con la que verifica. Cuando
// la consola asuma la emision, este binario deja de hacer falta: el formato del
// vale es el mismo que valida internal/tamper.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/fbolivar/nortis-agent/internal/tamper"
)

func main() {
	if len(os.Args) < 2 {
		uso()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	default:
		uso()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func uso() {
	fmt.Fprint(os.Stderr, `uninstall-token — autoridad de desbloqueo de Nortis (solo operaciones)

  keygen -out <dir>
      Genera el par de claves. Escribe console_pubkey.pem (para el agente) y
      console_privkey.pem (SECRETO, guardarlo con custodia). Nunca subir la
      privada a ningun repositorio ni al agente.

  sign -endpoint <endpoint_id> -priv <console_privkey.pem> [-ttl 30m]
      Firma un vale de desinstalacion para ESE equipo, valido durante -ttl.
      Se entrega al tecnico, que ejecuta:  nortis-agent unlock -token <vale>
`)
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", ".", "directorio de salida")
	if err := fs.Parse(args); err != nil {
		return err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	// La clave se guarda "cruda" (32/64 bytes) dentro del bloque PEM. Para
	// Ed25519 no hace falta el envoltorio SubjectPublicKeyInfo, y asi el agente
	// la lee sin depender de x509.
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "NORTIS CONSOLE ED25519 PUBLIC KEY", Bytes: pub})
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "NORTIS CONSOLE ED25519 PRIVATE KEY", Bytes: priv})

	if err := os.WriteFile(*out+"/console_pubkey.pem", pubPEM, 0o644); err != nil {
		return err
	}
	// La privada con permisos restrictivos: es la llave maestra de desinstalacion
	// de toda la flota.
	if err := os.WriteFile(*out+"/console_privkey.pem", privPEM, 0o600); err != nil {
		return err
	}

	fmt.Printf(`Par de claves generado en %s

  console_pubkey.pem   -> va al agente (empotrar con -ldflags o colocar en
                          %%ProgramData%%\Nortis\Agent\console_pubkey.pem)
  console_privkey.pem  -> SECRETO. Custodia. Nunca al repositorio ni al agente.
`, *out)
	return nil
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	endpoint := fs.String("endpoint", "", "endpoint_id del equipo a desbloquear")
	privPath := fs.String("priv", "console_privkey.pem", "ruta de la clave privada")
	ttl := fs.Duration("ttl", 30*time.Minute, "validez del vale")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *endpoint == "" {
		return fmt.Errorf("falta -endpoint")
	}

	priv, err := leerPrivada(*privPath)
	if err != nil {
		return err
	}

	ahora := time.Now().UTC()
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	token, err := tamper.Firmar(tamper.Vale{
		Motivo:     tamper.MotivoDesinstalar,
		EndpointID: *endpoint,
		EmitidoEn:  ahora,
		CaducaEn:   ahora.Add(*ttl),
		Nonce:      base64.RawURLEncoding.EncodeToString(nonce),
	}, priv)
	if err != nil {
		return err
	}

	fmt.Println(token)
	return nil
}

func leerPrivada(ruta string) (ed25519.PrivateKey, error) {
	datos, err := os.ReadFile(ruta)
	if err != nil {
		return nil, err
	}
	bloque, _ := pem.Decode(datos)
	if bloque == nil {
		return nil, fmt.Errorf("%s no contiene un bloque PEM valido", ruta)
	}
	if len(bloque.Bytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("la clave privada no tiene el tamano de una clave Ed25519")
	}
	return ed25519.PrivateKey(bloque.Bytes), nil
}
