package enforce

import "testing"

func TestDebeCuarentenar(t *testing.T) {
	permitidas := []string{`C:\Operaciones`}

	casos := []struct {
		nombre string
		ruta   string
		quiero bool
	}{
		{"documento fuera de la carpeta", `C:\Users\ana\Desktop\nomina.xlsx`, true},
		{"documento DENTRO de la permitida", `C:\Operaciones\nomina.xlsx`, false},
		{"documento en subcarpeta de la permitida", `C:\Operaciones\2026\cierre.pdf`, false},
		{"no es documento (ejecutable)", `C:\Users\ana\Desktop\juego.exe`, false},
		{"temporal del sistema se ignora", `C:\Users\ana\AppData\Local\Temp\algo.docx`, false},
		{"AppData se ignora", `C:\Users\ana\AppData\Roaming\app\datos.txt`, false},
		{"Windows se ignora", `C:\Windows\System32\config.txt`, false},
		{"el propio Nortis se ignora", `C:\ProgramData\Nortis\Agent\cola.txt`, false},
		{"documento en USB fuera de la permitida", `E:\robo\clientes.csv`, true},
	}

	for _, c := range casos {
		if got := DebeCuarentenar(c.ruta, permitidas); got != c.quiero {
			t.Errorf("%s: DebeCuarentenar(%q)=%v; quiero %v", c.nombre, c.ruta, got, c.quiero)
		}
	}
}

func TestSinCarpetasPermitidasNoRemedia(t *testing.T) {
	// Sin allowed_paths la regla no aplica: nada se retira, aunque sea un
	// documento en cualquier sitio.
	if DebeCuarentenar(`C:\Users\ana\Desktop\nomina.xlsx`, nil) {
		t.Fatal("sin carpetas permitidas no se debe cuarentenar nada")
	}
	if DebeCuarentenar(`C:\Users\ana\Desktop\nomina.xlsx`, []string{}) {
		t.Fatal("con lista vacia no se debe cuarentenar nada")
	}
}

func TestBajoAlgunaNormaliza(t *testing.T) {
	// Barra final y mayusculas no deben romper la comparacion.
	if !BajoAlguna(`D:\Compartido\a.txt`, []string{`d:\compartido\`}) {
		t.Fatal("la normalizacion de mayusculas/barra final fallo")
	}
	// Un prefijo que no es frontera de carpeta no cuenta: "C:\Oper" no contiene
	// a "C:\Operaciones".
	if BajoAlguna(`C:\Operaciones\a.txt`, []string{`C:\Oper`}) {
		t.Fatal("un prefijo que no es frontera de carpeta no debe contar como dentro")
	}
}
