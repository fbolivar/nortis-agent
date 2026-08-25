//go:build windows

package tamper

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
)

const soportado = true

// DACL del OBJETO DE SERVICIO, en SDDL. `D:P` = DACL protegido: no hereda ACEs
// del contenedor, de modo que nadie afloja la proteccion cambiando permisos mas
// arriba. Las letras son derechos de servicio:
//
//	CC QueryConfig · DC ChangeConfig · LC QueryStatus · SW EnumDependents
//	RP Start · WP Stop · DT PauseContinue · LO Interrogate · CR UserDefinedCtrl
//	RC ReadControl · SD Delete · WD WriteDAC · WO WriteOwner
//
// SYSTEM: control total. El servicio corre como SYSTEM y necesita poder
// reafirmar y aflojar su propio DACL; es tambien el UNICO que conserva WriteDAC,
// para que un administrador por si solo —sin vale— no pueda aflojar la
// proteccion.
//
// Administradores (BA): pueden verlo y arrancarlo, pero NO detenerlo (sin WP),
// NO borrarlo (sin SD), NO reconfigurarlo (sin DC) NI reescribir su DACL (sin
// WD). Quitar el agente les exige pasar por el desbloqueo autorizado.
//
// Usuarios autenticados (AU): solo consulta de estado. Un usuario normal no
// puede ni pararlo ni arrancarlo.
const (
	sddlServicioEndurecido = "D:P(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;AU)"

	// Aflojado: los administradores recuperan Stop, Delete y ChangeConfig para
	// que la desinstalacion pueda proceder. Se aplica SOLO tras validar un vale.
	sddlServicioAflojado = "D:P(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)"

	// DACL del DIRECTORIO DE DATOS. OICI = heredan objetos y contenedores.
	// SYSTEM y administradores con control total; usuarios autenticados con solo
	// lectura, para que no puedan borrar la cola de eventos ni la credencial. El
	// borrado de la evidencia es justo lo que un usuario que va a filtrar
	// intentaria; aqui el sistema de archivos se lo impide.
	sddlDirectorioEndurecido = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;AU)"
)

// aplicarSDDLServicio pone en el objeto de servicio el DACL descrito por sddl.
func aplicarSDDLServicio(nombre, sddl string) error {
	h, err := abrirServicio(nombre, windows.WRITE_DAC|windows.READ_CONTROL)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseServiceHandle(h) }()

	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("SDDL invalido: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("no se pudo extraer el DACL del SDDL: %w", err)
	}

	// PROTECTED_DACL: se descarta cualquier herencia; el DACL queda tal cual.
	err = windows.SetSecurityInfo(
		h, windows.SE_SERVICE,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
	if err != nil {
		return fmt.Errorf("no se pudo escribir el DACL del servicio: %w", err)
	}
	return nil
}

func endurecerServicio(nombre string) error {
	return aplicarSDDLServicio(nombre, sddlServicioEndurecido)
}

func aflojarServicio(nombre string) error {
	return aplicarSDDLServicio(nombre, sddlServicioAflojado)
}

func servicioEndurecido(nombre string) (bool, error) {
	h, err := abrirServicio(nombre, windows.READ_CONTROL)
	if err != nil {
		return false, err
	}
	defer func() { _ = windows.CloseServiceHandle(h) }()

	sd, err := windows.GetSecurityInfo(h, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, fmt.Errorf("no se pudo leer el DACL del servicio: %w", err)
	}
	// Endurecido = los administradores NO tienen permiso de parada (Stop) en su
	// ACE. Es la comprobacion mas honesta de que la proteccion esta puesta: si
	// pueden pararlo, no lo esta.
	return !aceConcedeStop(sd.String(), "BA"), nil
}

func endurecerDirectorio(dir string) error {
	sd, err := windows.SecurityDescriptorFromString(sddlDirectorioEndurecido)
	if err != nil {
		return fmt.Errorf("SDDL de directorio invalido: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	err = windows.SetNamedSecurityInfo(
		dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
	if err != nil {
		return fmt.Errorf("no se pudo escribir el DACL del directorio: %w", err)
	}
	return nil
}

func directorioEndurecido(dir string) (bool, error) {
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	// Endurecido = el DACL esta protegido (no hereda). Nuestro endurecimiento
	// siempre pone la bandera `P`; un directorio que herede del padre no la
	// tiene. Se leen las banderas del DACL (lo que hay entre "D:" y el primer
	// ACE) y se busca esa `P`.
	return daclProtegido(sd.String()), nil
}

// daclProtegido indica si la seccion DACL del SDDL lleva la bandera P (protegido,
// no hereda). Las banderas van entre "D:" y el primer "(".
func daclProtegido(sddl string) bool {
	i := strings.Index(sddl, "D:")
	if i < 0 {
		return false
	}
	flags := sddl[i+2:]
	if j := strings.IndexByte(flags, '('); j >= 0 {
		flags = flags[:j]
	}
	return strings.ContainsRune(flags, 'P')
}

// abrirServicio conecta con el gestor de servicios y abre el servicio con el
// acceso pedido. Aisla el par de llamadas para que endurecer, aflojar y leer no
// repitan la coreografia de handles.
func abrirServicio(nombre string, acceso uint32) (windows.Handle, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, fmt.Errorf("no se pudo abrir el gestor de servicios: %w", err)
	}
	defer func() { _ = windows.CloseServiceHandle(scm) }()

	nombreW, err := windows.UTF16PtrFromString(nombre)
	if err != nil {
		return 0, err
	}
	h, err := windows.OpenService(scm, nombreW, acceso)
	if err != nil {
		return 0, fmt.Errorf("no se pudo abrir el servicio %q (¿esta instalado? ¿hay privilegios?): %w", nombre, err)
	}
	return h, nil
}

// aceConcedeStop indica si, en el SDDL dado, el ACE de la cuenta `sid` concede el
// derecho de parada del servicio. Acepta la forma de letras (…WP…) y la forma
// hexadecimal (0x…), porque Windows devuelve una u otra segun el caso.
func aceConcedeStop(sddl, sid string) bool {
	marca := ";;;" + sid + ")"
	for _, ace := range trocearACEs(sddl) {
		if !strings.HasSuffix(ace, marca) {
			continue
		}
		campos := strings.Split(strings.Trim(ace, "()"), ";")
		if len(campos) < 3 {
			continue
		}
		derechos := campos[2]
		if strings.HasPrefix(derechos, "0x") || strings.HasPrefix(derechos, "0X") {
			var mask uint64
			_, _ = fmt.Sscanf(derechos, "0x%x", &mask)
			return mask&0x20 != 0 // SERVICE_STOP
		}
		return strings.Contains(derechos, "WP")
	}
	return false
}

// trocearACEs parte la cadena DACL en sus ACEs individuales "(...)".
func trocearACEs(sddl string) []string {
	var aces []string
	for {
		abre := strings.IndexByte(sddl, '(')
		if abre < 0 {
			break
		}
		cierra := strings.IndexByte(sddl[abre:], ')')
		if cierra < 0 {
			break
		}
		aces = append(aces, sddl[abre:abre+cierra+1])
		sddl = sddl[abre+cierra+1:]
	}
	return aces
}
