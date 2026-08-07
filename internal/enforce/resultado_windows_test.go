//go:build windows

package enforce

import "testing"

// La regla 3 del paquete: lo que no se puede aplicar se dice. La primera version
// devolvia el modo solicitado aunque la escritura hubiera fallado, y el resumen
// anunciaba "usb=read_only" sobre un equipo donde no se aplico nada.
//
// Un panel que muestra "protegido" un equipo con el registro sin tocar es peor
// que uno que admite el hueco: nadie va a ir a mirar el log.
func TestUnEquipoSinAplicarNoSeDaPorCubierto(t *testing.T) {
	casos := []struct {
		nombre   string
		res      Resultado
		cubierto bool
	}{
		{
			nombre:   "todo aplicado",
			res:      Resultado{USB: "read_only", USBSolicitado: "read_only", Dominios: 12},
			cubierto: true,
		},
		{
			nombre:   "sin dominios que bloquear es cobertura valida",
			res:      Resultado{USB: "allow", USBSolicitado: "allow", Dominios: 0},
			cubierto: true,
		},
		{
			nombre:   "el registro fallo",
			res:      Resultado{USB: "no_aplicado", USBSolicitado: "block", Dominios: 3},
			cubierto: false,
		},
		{
			nombre:   "el archivo hosts fallo",
			res:      Resultado{USB: "read_only", USBSolicitado: "read_only", Dominios: -1},
			cubierto: false,
		},
		{
			nombre:   "fallaron los dos",
			res:      Resultado{USB: "no_aplicado", USBSolicitado: "block", Dominios: -1},
			cubierto: false,
		},
	}

	for _, c := range casos {
		if got := c.res.Cubierto(); got != c.cubierto {
			t.Errorf("%s: Cubierto()=%v, se esperaba %v", c.nombre, got, c.cubierto)
		}
	}
}

// -1 y 0 son estados distintos: "no se pudo escribir el archivo hosts" y "la
// politica no pedia bloquear ningun dominio". Confundirlos oculta un equipo
// desprotegido detras de un numero que parece normal.
func TestCeroDominiosNoEsLoMismoQueFalloAlEscribir(t *testing.T) {
	sinNada := Resultado{USB: "allow", Dominios: 0}
	fallo := Resultado{USB: "allow", Dominios: -1}

	if !sinNada.Cubierto() {
		t.Error("una politica sin dominios que bloquear si esta cubierta")
	}
	if fallo.Cubierto() {
		t.Error("un fallo al escribir el archivo hosts no puede darse por cubierto")
	}
}
