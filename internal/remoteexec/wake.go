package remoteexec

import (
	"context"
	"fmt"
	"net"
)

// EjecutarWake envia un paquete magico de Wake-on-LAN a la MAC indicada por la
// red local (difusion UDP al puerto 9). Lo ejecuta un agente EN LINEA de la misma
// red que el equipo apagado; el destino, si tiene WOL habilitado en su BIOS/red,
// se enciende. No necesita Windows: es puro socket.
func EjecutarWake(_ context.Context, p WakePayload) (int, string, error) {
	mac, err := net.ParseMAC(p.MAC)
	if err != nil || len(mac) != 6 {
		return -1, "", fmt.Errorf("MAC invalida: %q", p.MAC)
	}

	// Paquete magico: 6 bytes 0xFF seguidos de la MAC repetida 16 veces.
	paquete := make([]byte, 0, 102)
	for i := 0; i < 6; i++ {
		paquete = append(paquete, 0xFF)
	}
	for i := 0; i < 16; i++ {
		paquete = append(paquete, mac...)
	}

	conn, err := net.Dial("udp", "255.255.255.255:9")
	if err != nil {
		return -1, "", fmt.Errorf("no se pudo abrir el socket de difusion: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write(paquete); err != nil {
		return -1, "", fmt.Errorf("no se pudo enviar el paquete WOL: %w", err)
	}
	return 0, "paquete Wake-on-LAN enviado a " + p.MAC, nil
}
