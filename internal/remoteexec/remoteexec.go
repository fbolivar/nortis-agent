// Package remoteexec ejecuta las tareas administrativas que la consola encarga
// (instalar un MSI, colocar un archivo, reiniciar). La regla de oro: NADA se
// ejecuta sin verificar antes la firma Ed25519 de la consola sobre los bytes
// canonicos de la tarea. El agente no confia en la base ni en la API — solo en la
// clave privada de la consola, que no vive en ninguna de las dos.
package remoteexec

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// signPrefix y la construccion de BytesCanonicos DEBEN coincidir byte a byte con
// la consola (src/shared/lib/agent-signing.ts). Si divergen, ninguna firma
// verifica.
const signPrefix = "nortis-task-v1"

// BytesCanonicos son los bytes exactos sobre los que se calcula/verifica la
// firma: prefijo, endpoint, tipo y el payload TAL CUAL llego (los mismos bytes
// que la consola guardo y firmo).
func BytesCanonicos(endpointID, kind, payload string) []byte {
	return []byte(signPrefix + "\n" + endpointID + "\n" + kind + "\n" + payload)
}

// VerificarFirma comprueba la firma Ed25519 de la consola. Es la unica puerta:
// si devuelve error, la tarea NO se ejecuta.
func VerificarFirma(pub ed25519.PublicKey, endpointID, kind, payload, firmaB64 string) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("clave publica de la consola no disponible o invalida")
	}
	firma, err := base64.StdEncoding.DecodeString(firmaB64)
	if err != nil {
		return fmt.Errorf("la firma no es base64 valido: %w", err)
	}
	if !ed25519.Verify(pub, BytesCanonicos(endpointID, kind, payload), firma) {
		return errors.New("firma invalida: la tarea no la emitio la consola")
	}
	return nil
}

// InstallMSIPayload es el contenido de una tarea install_msi.
type InstallMSIPayload struct {
	URL      string `json:"url"`
	SHA256   string `json:"sha256"`
	Args     string `json:"args"`
	NotAfter int64  `json:"not_after"` // epoch en segundos; caducidad firmada
}

// ParseInstallMSI lee y valida el payload de una tarea install_msi.
func ParseInstallMSI(payload string) (InstallMSIPayload, error) {
	var p InstallMSIPayload
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		return p, fmt.Errorf("payload install_msi ilegible: %w", err)
	}
	if p.URL == "" || len(p.SHA256) != 64 {
		return p, errors.New("payload install_msi incompleto (url/sha256)")
	}
	return p, nil
}

// Vencida indica si la caducidad firmada ya paso. Una tarea vencida se rechaza
// aunque la firma sea valida: acota la reejecucion de una tarea copiada.
func Vencida(notAfter int64, ahora time.Time) bool {
	return notAfter > 0 && ahora.Unix() > notAfter
}

// --- wipe: borrado remoto de datos ---

// WipePayload es el contenido de una tarea wipe. Solo lleva caducidad: el alcance
// del borrado NO lo decide la consola por seguridad (una ruta firmada arbitraria
// seria un borrado de cualquier cosa); el agente borra un conjunto fijo y acotado
// —las carpetas de documentos del usuario y las unidades extraibles—.
type WipePayload struct {
	NotAfter int64 `json:"not_after"`
}

// ParseWipe lee el payload de una tarea wipe.
func ParseWipe(payload string) (WipePayload, error) {
	var p WipePayload
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		return p, fmt.Errorf("payload wipe ilegible: %w", err)
	}
	return p, nil
}

// --- screenshot bajo demanda / message / kill / uninstall ---

// ScreenshotPayload solo lleva caducidad; la captura la hace el agente.
type ScreenshotPayload struct {
	NotAfter int64 `json:"not_after"`
}

// ParseScreenshot lee el payload de una tarea screenshot.
func ParseScreenshot(payload string) (ScreenshotPayload, error) {
	var p ScreenshotPayload
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		return p, fmt.Errorf("payload screenshot ilegible: %w", err)
	}
	return p, nil
}

// MessagePayload es un aviso que se muestra al usuario.
type MessagePayload struct {
	Title    string `json:"title"`
	Body     string `json:"body"`
	NotAfter int64  `json:"not_after"`
}

// ParseMessage valida el aviso: cuerpo obligatorio, longitudes acotadas.
func ParseMessage(payload string) (MessagePayload, error) {
	var p MessagePayload
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		return p, fmt.Errorf("payload message ilegible: %w", err)
	}
	if strings.TrimSpace(p.Body) == "" {
		return p, errors.New("el mensaje no puede estar vacio")
	}
	if len(p.Title) > 200 || len(p.Body) > 2000 {
		return p, errors.New("mensaje demasiado largo")
	}
	return p, nil
}

// KillPayload es el nombre del ejecutable a terminar.
type KillPayload struct {
	Name     string `json:"name"`
	NotAfter int64  `json:"not_after"`
}

// ParseKill valida el nombre del proceso.
func ParseKill(payload string) (KillPayload, error) {
	var p KillPayload
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		return p, fmt.Errorf("payload kill ilegible: %w", err)
	}
	if strings.TrimSpace(p.Name) == "" {
		return p, errors.New("falta el nombre del proceso")
	}
	return p, nil
}

// UninstallPayload es el nombre EXACTO del programa (DisplayName) a desinstalar.
type UninstallPayload struct {
	Name     string `json:"name"`
	NotAfter int64  `json:"not_after"`
}

// ParseUninstall valida el nombre del programa.
func ParseUninstall(payload string) (UninstallPayload, error) {
	var p UninstallPayload
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		return p, fmt.Errorf("payload uninstall ilegible: %w", err)
	}
	if strings.TrimSpace(p.Name) == "" {
		return p, errors.New("falta el nombre del programa")
	}
	return p, nil
}

// --- wake: encender un equipo por Wake-on-LAN ---

// WakePayload lleva la MAC del equipo a despertar. Lo envia un agente EN LINEA de
// la misma red (el equipo destino esta apagado y no puede hacerlo el mismo).
type WakePayload struct {
	MAC      string `json:"mac"`
	NotAfter int64  `json:"not_after"`
}

// ParseWake valida la MAC.
func ParseWake(payload string) (WakePayload, error) {
	var p WakePayload
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		return p, fmt.Errorf("payload wake ilegible: %w", err)
	}
	if strings.TrimSpace(p.MAC) == "" {
		return p, errors.New("falta la MAC del equipo a encender")
	}
	return p, nil
}

// --- scan_av: escaneo de antivirus bajo demanda ---

// ScanPayload pide un escaneo de Windows Defender. Type: "quick" o "full".
type ScanPayload struct {
	Type     string `json:"type"`
	NotAfter int64  `json:"not_after"`
}

// ParseScan valida el tipo de escaneo.
func ParseScan(payload string) (ScanPayload, error) {
	var p ScanPayload
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		return p, fmt.Errorf("payload scan_av ilegible: %w", err)
	}
	if p.Type != "quick" && p.Type != "full" {
		return p, fmt.Errorf("tipo de escaneo no soportado: %q", p.Type)
	}
	return p, nil
}

// --- account_action: respuesta sobre una cuenta local ---

// AccountActionPayload pide una accion sobre una cuenta local. Action:
// disable | enable | delete | logoff. Target: nombre de la cuenta/usuario.
type AccountActionPayload struct {
	Action   string `json:"action"`
	Target   string `json:"target"`
	NotAfter int64  `json:"not_after"`
}

// cuentasProtegidas nunca se borran ni deshabilitan, aunque la consola lo pida:
// tumbar la cuenta integrada de administrador o al propio SYSTEM dejaria el
// equipo sin salida. La consola es de confianza, pero un error humano no debe
// poder inutilizar la maquina.
var cuentasProtegidas = map[string]bool{
	"administrator": true, "administrador": true, "system": true,
	"defaultaccount": true, "wdagutilityaccount": true,
}

// ParseAccountAction valida la accion y el objetivo.
func ParseAccountAction(payload string) (AccountActionPayload, error) {
	var p AccountActionPayload
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		return p, fmt.Errorf("payload account_action ilegible: %w", err)
	}
	switch p.Action {
	case "disable", "enable", "delete", "logoff":
	default:
		return p, fmt.Errorf("accion de cuenta no soportada: %q", p.Action)
	}
	if strings.TrimSpace(p.Target) == "" {
		return p, errors.New("falta la cuenta objetivo")
	}
	// El nombre puede venir como "EQUIPO\usuario"; se compara la parte final.
	corto := p.Target
	if i := strings.LastIndex(corto, `\`); i >= 0 {
		corto = corto[i+1:]
	}
	if (p.Action == "delete" || p.Action == "disable") && cuentasProtegidas[strings.ToLower(corto)] {
		return p, fmt.Errorf("la cuenta %q esta protegida y no se puede %s", corto, p.Action)
	}
	return p, nil
}

// --- harden: endurecimiento remoto (firewall, defender) ---

// HardenPayload pide activar protecciones. Targets: "firewall", "defender".
type HardenPayload struct {
	Targets  []string `json:"targets"`
	NotAfter int64    `json:"not_after"`
}

// ParseHarden valida los objetivos.
func ParseHarden(payload string) (HardenPayload, error) {
	var p HardenPayload
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		return p, fmt.Errorf("payload harden ilegible: %w", err)
	}
	if len(p.Targets) == 0 {
		return p, errors.New("no se indico que endurecer")
	}
	for _, t := range p.Targets {
		if t != "firewall" && t != "defender" {
			return p, fmt.Errorf("objetivo de endurecimiento no soportado: %q", t)
		}
	}
	return p, nil
}

// --- network_isolate: aislamiento de red (cuarentena) ---

// IsolatePayload activa o revierte el aislamiento. Al aislar se bloquea toda la
// red SALVO: DNS, HTTPS de salida (para que el agente siga reportando y el
// aislamiento sea reversible desde la consola) y RDP de entrada (gestion).
type IsolatePayload struct {
	Enable   bool  `json:"enable"`
	NotAfter int64 `json:"not_after"`
}

// ParseIsolate lee el payload de aislamiento.
func ParseIsolate(payload string) (IsolatePayload, error) {
	var p IsolatePayload
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		return p, fmt.Errorf("payload network_isolate ilegible: %w", err)
	}
	return p, nil
}

// --- schedule_script: script recurrente ---

// ScheduleScriptPayload define un script que el agente ejecuta cada
// EveryMinutes, hasta NotAfter. ID identifica la programacion para poder
// reemplazarla o quitarla (EveryMinutes = 0).
type ScheduleScriptPayload struct {
	ID           string `json:"id"`
	Interpreter  string `json:"interpreter"` // powershell | cmd
	Script       string `json:"script"`
	EveryMinutes int    `json:"every_minutes"`
	NotAfter     int64  `json:"not_after"`
}

// ParseScheduleScript valida la programacion.
func ParseScheduleScript(payload string) (ScheduleScriptPayload, error) {
	var p ScheduleScriptPayload
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		return p, fmt.Errorf("payload schedule_script ilegible: %w", err)
	}
	if strings.TrimSpace(p.ID) == "" {
		return p, errors.New("falta el identificador de la programacion")
	}
	// EveryMinutes = 0 significa "quitar esta programacion"; en ese caso no se
	// exige script ni interprete.
	if p.EveryMinutes > 0 {
		if p.Interpreter != "powershell" && p.Interpreter != "cmd" {
			return p, fmt.Errorf("interprete no soportado: %q", p.Interpreter)
		}
		if strings.TrimSpace(p.Script) == "" {
			return p, errors.New("script vacio")
		}
	}
	return p, nil
}

// descargarVerificado baja `url` a un archivo temporal con extension `ext` y
// comprueba que su sha256 coincide con `shaHex`. Si no coincide, borra el archivo
// y devuelve error: nunca se ejecuta un binario sin verificar su integridad.
// Devuelve la ruta del archivo temporal (el llamante debe borrarlo).
func descargarVerificado(ctx context.Context, url, shaHex, ext string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("descarga fallida: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("descarga devolvio HTTP %d", resp.StatusCode)
	}

	f, err := os.CreateTemp("", "nortis-task-*"+ext)
	if err != nil {
		return "", err
	}
	tmp := f.Name()

	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return "", fmt.Errorf("no se pudo escribir la descarga: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}

	got := hex.EncodeToString(h.Sum(nil))
	if got != shaHex {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("sha256 no coincide: esperado %s, obtenido %s", shaHex, got)
	}
	return tmp, nil
}

// --- push_file: colocar un archivo en el equipo ---

// PushFilePayload es el contenido de una tarea push_file.
type PushFilePayload struct {
	URL      string `json:"url"`
	SHA256   string `json:"sha256"`
	DestPath string `json:"dest_path"`
	NotAfter int64  `json:"not_after"`
}

// ParsePushFile lee y valida el payload de una tarea push_file. Exige una ruta
// destino ABSOLUTA y sin "..": la consola encarga la accion, pero el agente no
// deja que una ruta relativa o con traversal escriba fuera de donde se pretende.
func ParsePushFile(payload string) (PushFilePayload, error) {
	var p PushFilePayload
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		return p, fmt.Errorf("payload push_file ilegible: %w", err)
	}
	if p.URL == "" || len(p.SHA256) != 64 || p.DestPath == "" {
		return p, errors.New("payload push_file incompleto (url/sha256/dest_path)")
	}
	if !filepath.IsAbs(p.DestPath) || strings.Contains(p.DestPath, "..") {
		return p, fmt.Errorf("ruta destino invalida: %q", p.DestPath)
	}
	return p, nil
}

// EjecutarPushFile descarga el archivo (verificando sha256) y lo coloca en
// DestPath, creando la carpeta si falta. Devuelve exito y la ruta final.
func EjecutarPushFile(ctx context.Context, p PushFilePayload) (int, string, error) {
	tmp, err := descargarVerificado(ctx, p.URL, p.SHA256, filepath.Ext(p.DestPath))
	if err != nil {
		return -1, "", err
	}
	// Si el movimiento tiene exito, tmp deja de existir; si falla, se limpia.
	movido := false
	defer func() {
		if !movido {
			_ = os.Remove(tmp)
		}
	}()

	if err := os.MkdirAll(filepath.Dir(p.DestPath), 0o750); err != nil {
		return -1, "", fmt.Errorf("no se pudo crear la carpeta destino: %w", err)
	}
	if err := moverArchivo(tmp, p.DestPath); err != nil {
		return -1, "", err
	}
	movido = true
	return 0, "archivo colocado en " + p.DestPath, nil
}

// moverArchivo mueve src a dst. Intenta os.Rename (instantaneo en el mismo
// volumen) y, si falla porque cruzan de unidad, copia y borra el origen.
func moverArchivo(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	_ = os.Remove(src)
	return nil
}

// --- evidence_snapshot: captura forense de un equipo en un clic ---

// EvidenceSnapshotPayload solo lleva caducidad: el snapshot lo compone el agente
// con lo que ya recolecta (procesos, puertos, autoarranque, cuentas, USB). Es una
// foto CONGELADA para adjuntar a un incidente, distinta del inventario en vivo.
type EvidenceSnapshotPayload struct {
	NotAfter int64 `json:"not_after"`
}

// ParseEvidenceSnapshot lee el payload de una tarea evidence_snapshot.
func ParseEvidenceSnapshot(payload string) (EvidenceSnapshotPayload, error) {
	var p EvidenceSnapshotPayload
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		return p, fmt.Errorf("payload evidence_snapshot ilegible: %w", err)
	}
	return p, nil
}

// --- ediscovery_scan: descubrimiento de datos en reposo ---

// EDiscoveryPayload pide un barrido de rutas locales aplicando la clasificacion
// por contenido, para saber DONDE vive el dato sensible sin esperar a que alguien
// lo mueva (la funcion "eDiscovery" de Safetica / Endpoint Protector). Solo se
// reportan metadatos: ruta, clase, tamaño y fecha; nunca el contenido.
type EDiscoveryPayload struct {
	Paths    []string `json:"paths"`
	MaxFiles int      `json:"max_files"`
	MaxHits  int      `json:"max_hits"`
	NotAfter int64    `json:"not_after"`
}

// ParseEDiscovery valida el payload: al menos una ruta, todas absolutas y sin
// "..". Fija topes por defecto para que un barrido nunca sea ilimitado.
func ParseEDiscovery(payload string) (EDiscoveryPayload, error) {
	var p EDiscoveryPayload
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		return p, fmt.Errorf("payload ediscovery_scan ilegible: %w", err)
	}
	limpias := make([]string, 0, len(p.Paths))
	for _, ruta := range p.Paths {
		ruta = strings.TrimSpace(ruta)
		if ruta == "" {
			continue
		}
		if !filepath.IsAbs(ruta) || strings.Contains(ruta, "..") {
			return p, fmt.Errorf("ruta invalida: %q", ruta)
		}
		limpias = append(limpias, ruta)
	}
	if len(limpias) == 0 {
		return p, errors.New("no se indico ninguna ruta a barrer")
	}
	p.Paths = limpias
	if p.MaxFiles <= 0 || p.MaxFiles > 200000 {
		p.MaxFiles = 20000
	}
	if p.MaxHits <= 0 || p.MaxHits > 5000 {
		p.MaxHits = 1000
	}
	return p, nil
}

// --- run_script: ejecutar un script firmado ---

// RunScriptPayload es el contenido de una tarea run_script.
type RunScriptPayload struct {
	Interpreter string `json:"interpreter"` // powershell | cmd
	Script      string `json:"script"`
	NotAfter    int64  `json:"not_after"`
}

// ParseRunScript lee y valida el payload de una tarea run_script. Acota el
// interprete a powershell o cmd: no se ejecuta un binario arbitrario nombrado
// desde la consola, solo un script bajo un interprete conocido.
func ParseRunScript(payload string) (RunScriptPayload, error) {
	var p RunScriptPayload
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		return p, fmt.Errorf("payload run_script ilegible: %w", err)
	}
	if p.Interpreter != "powershell" && p.Interpreter != "cmd" {
		return p, fmt.Errorf("interprete no soportado: %q", p.Interpreter)
	}
	if strings.TrimSpace(p.Script) == "" {
		return p, errors.New("script vacio")
	}
	return p, nil
}
