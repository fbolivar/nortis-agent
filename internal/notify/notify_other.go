//go:build !windows

package notify

// Fuera de Windows no hay MessageBox. El stub deja compilable el subcomando en
// otras plataformas (CI); el agente solo se ejecuta en Windows.
func Mostrar(string, string) error { return nil }
