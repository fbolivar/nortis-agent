// Package tamper implementa la proteccion contra manipulacion del agente.
//
// El modelo es "resistencia con autorizacion", no "imposible de eliminar":
//
//   - El usuario SIN privilegios no puede detener, pausar ni desinstalar el
//     servicio, ni borrar la cola de eventos. Lo impone el sistema operativo a
//     traves de un DACL restrictivo en el objeto de servicio y en el directorio
//     de datos, no un vigilante en espacio de usuario que se pueda matar.
//   - Quitar el agente exige ser administrador local Y presentar un vale de
//     desinstalacion firmado por la consola, ligado a ESTE equipo y con
//     caducidad. Es el mismo modelo que usa el EDR serio: nada legitimo es
//     irreversible, pero quitarlo requiere autoridad demostrable.
//
// Este archivo es la mitad PORTABLE y verificable del modelo: la criptografia
// del vale. No toca el sistema operativo, asi que compila y se prueba en
// cualquier plataforma. La mitad que habla con Windows vive en los archivos con
// sufijo _windows.
package tamper

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Motivo obliga a que un vale diga para que sirve. Un vale de desinstalacion no
// debe poder reutilizarse como cualquier otra cosa que algun dia firmemos con la
// misma clave: el motivo entra en la firma.
const MotivoDesinstalar = "uninstall"

// margenReloj tolera un desfase razonable entre el reloj de la consola que
// emitio el vale y el del equipo que lo valida. Sin margen, un portatil con el
// reloj cinco minutos atrasado rechazaria un vale recien emitido y el tecnico
// veria un fallo que no sabe explicar.
const margenReloj = 5 * time.Minute

// Errores de verificacion. Se distinguen a proposito: "caducado" y "no es para
// este equipo" mandan a sitios distintos a quien depura, y mezclarlos en un
// generico "vale invalido" convierte el soporte en adivinanza.
var (
	ErrValeMalFormado   = errors.New("el vale de desinstalacion esta mal formado")
	ErrFirmaInvalida    = errors.New("la firma del vale no corresponde a la clave de la consola")
	ErrValeCaducado     = errors.New("el vale de desinstalacion ha caducado")
	ErrValeAunNoValido  = errors.New("el vale de desinstalacion aun no es valido (revise el reloj)")
	ErrValeOtroEquipo   = errors.New("el vale fue emitido para otro equipo")
	ErrMotivoInesperado = errors.New("el vale no autoriza una desinstalacion")
)

// Vale es la carga util que la consola firma para autorizar una desinstalacion.
//
// Lleva el endpoint_id DENTRO de la firma para que un vale robado de un equipo
// no valga en otro: quien intercepte el de un portatil no puede desinstalar toda
// la flota con el. Y lleva caducidad para que un vale filtrado no sea una llave
// maestra permanente.
type Vale struct {
	Motivo     string    `json:"motivo"`
	EndpointID string    `json:"endpoint_id"`
	EmitidoEn  time.Time `json:"emitido_en"`
	CaducaEn   time.Time `json:"caduca_en"`
	// Nonce hace que dos vales para el mismo equipo y ventana no sean identicos.
	// No lo consumimos contra una lista (el agente puede estar sin red), pero
	// deja rastro distinto de cada emision en el log de auditoria.
	Nonce string `json:"nonce"`
}

// Firmar produce la representacion de transporte del vale: base64url(json) del
// vale, un punto, y base64url de la firma Ed25519 sobre ESOS bytes de texto.
//
// Se firma el texto ya codificado, no el JSON crudo, para no depender de que dos
// serializadores de JSON produzcan exactamente los mismos bytes. El verificador
// valida sobre lo que recibe por el cable, sin volver a serializar nada.
//
// Vive aqui, junto al verificador, para que el formato tenga una sola definicion.
// La clave PRIVADA nunca esta en el agente: quien llama a Firmar es la
// herramienta de operaciones (tools/uninstall-token) o, en el futuro, la consola.
func Firmar(v Vale, priv ed25519.PrivateKey) (string, error) {
	cuerpo, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	cuerpoB64 := base64.RawURLEncoding.EncodeToString(cuerpo)
	firma := ed25519.Sign(priv, []byte(cuerpoB64))
	firmaB64 := base64.RawURLEncoding.EncodeToString(firma)
	return cuerpoB64 + "." + firmaB64, nil
}

// VerificarCon comprueba un vale contra una clave publica concreta.
//
// Es la version pura: no depende de la clave fijada en el binario, asi que las
// pruebas pueden generar su propio par de claves. Verificar comprueba, en orden,
// que la firma es de esa clave, que el motivo es el esperado, que el vale es para
// este equipo y que estamos dentro de su ventana de validez.
func VerificarCon(pub ed25519.PublicKey, token, endpointID string, ahora time.Time) (*Vale, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("clave publica de la consola invalida")
	}

	punto := strings.IndexByte(token, '.')
	if punto <= 0 || punto >= len(token)-1 {
		return nil, ErrValeMalFormado
	}
	cuerpoB64, firmaB64 := token[:punto], token[punto+1:]

	firma, err := base64.RawURLEncoding.DecodeString(firmaB64)
	if err != nil || len(firma) != ed25519.SignatureSize {
		return nil, ErrValeMalFormado
	}

	// La firma se verifica ANTES de mirar el contenido: no se toma ninguna
	// decision con datos que aun no se sabe si son autenticos.
	if !ed25519.Verify(pub, []byte(cuerpoB64), firma) {
		return nil, ErrFirmaInvalida
	}

	cuerpo, err := base64.RawURLEncoding.DecodeString(cuerpoB64)
	if err != nil {
		return nil, ErrValeMalFormado
	}
	var v Vale
	if err := json.Unmarshal(cuerpo, &v); err != nil {
		return nil, ErrValeMalFormado
	}

	if v.Motivo != MotivoDesinstalar {
		return nil, ErrMotivoInesperado
	}
	// La comparacion de equipo distingue mayusculas: los UUID de la consola son
	// canonicos en minuscula y aceptar variaciones solo abre hueco a confusiones.
	if v.EndpointID != endpointID {
		return nil, ErrValeOtroEquipo
	}
	if ahora.After(v.CaducaEn.Add(margenReloj)) {
		return nil, ErrValeCaducado
	}
	if ahora.Before(v.EmitidoEn.Add(-margenReloj)) {
		return nil, ErrValeAunNoValido
	}

	return &v, nil
}
