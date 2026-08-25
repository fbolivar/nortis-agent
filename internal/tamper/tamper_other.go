//go:build !windows

package tamper

// Fuera de Windows la proteccion no existe: no hay gestor de servicios ni DACL
// que endurecer. Estas implementaciones dejan el paquete compilable en CU para
// que el nucleo criptografico del vale se pruebe sin un runner de Windows, y
// devuelven ErrNoSoportado si alguien las invoca por error.

const soportado = false

func endurecerServicio(string) error            { return ErrNoSoportado }
func aflojarServicio(string) error              { return ErrNoSoportado }
func servicioEndurecido(string) (bool, error)   { return false, ErrNoSoportado }
func endurecerDirectorio(string) error          { return ErrNoSoportado }
func directorioEndurecido(string) (bool, error) { return false, ErrNoSoportado }
