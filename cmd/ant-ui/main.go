package main

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/chengyaolee/AnonymousAnt/pkg/ipc"
	"github.com/chengyaolee/AnonymousAnt/pkg/security"
)

//go:embed index.html
var uiHTML string

type UIServer struct {
	ipcClient *ipc.Client
	sockPath  string
}

func main() {
	port := flag.Int("port", 47820, "Local UI web port")
	sockPath := flag.String("sock", ipc.DefaultSocketPath, "Daemon IPC socket path")
	noBrowser := flag.Bool("no-browser", false, "Do not auto-open browser")
	flag.Parse()

	security.Info("Starting AnonymousAnt Desktop UI on http://127.0.0.1:%d", *port)

	server := &UIServer{
		sockPath: *sockPath,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", server.handleHome)
	mux.HandleFunc("/api/status", server.handleStatus)
	mux.HandleFunc("/api/connect", server.handleConnect)
	mux.HandleFunc("/api/disconnect", server.handleDisconnect)
	mux.HandleFunc("/api/events", server.handleEvents)
	mux.HandleFunc("/api/start-daemon", server.handleStartDaemon)

	url := fmt.Sprintf("http://127.0.0.1:%d", *port)
	if !*noBrowser {
		go func() {
			time.Sleep(300 * time.Millisecond)
			openBrowser(url)
		}()
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		security.Error("Failed to bind UI port: %v", err)
		return
	}
	defer ln.Close()

	security.Info("AnonymousAnt UI ready at %s", url)
	_ = http.Serve(ln, mux)
}

func (s *UIServer) getClient() (*ipc.Client, error) {
	return ipc.NewClient(s.sockPath)
}

func (s *UIServer) handleHome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(uiHTML))
}

func (s *UIServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	client, err := s.getClient()
	if err != nil {
		jsonResponse(w, http.StatusOK, map[string]any{
			"daemon_running": false,
			"connected":      false,
			"error":          "Daemon is not running. Start 'ant-daemon' first.",
		})
		return
	}
	defer client.Close()

	status, err := client.GetStatus()
	if err != nil {
		jsonResponse(w, http.StatusOK, map[string]any{
			"daemon_running": true,
			"connected":      false,
			"error":          err.Error(),
		})
		return
	}

	jsonResponse(w, http.StatusOK, map[string]any{
		"daemon_running": true,
		"status":         status,
	})
}

func (s *UIServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var params ipc.ConnectParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]any{"error": "invalid json"})
		return
	}

	client, err := s.getClient()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]any{"error": "daemon unavailable"})
		return
	}
	defer client.Close()

	resp, err := client.Connect(params)
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	jsonResponse(w, http.StatusOK, resp)
}

func (s *UIServer) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	client, err := s.getClient()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]any{"error": "daemon unavailable"})
		return
	}
	defer client.Close()

	resp, err := client.Disconnect()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	jsonResponse(w, http.StatusOK, resp)
}

func (s *UIServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			client, err := s.getClient()
			var data []byte
			if err != nil {
				data, _ = json.Marshal(map[string]any{"daemon_running": false, "connected": false})
			} else {
				status, _ := client.GetStatus()
				client.Close()
				data, _ = json.Marshal(map[string]any{"daemon_running": true, "status": status})
			}
			fmt.Fprintf(w, "data: %s\n\n", string(data))
			flusher.Flush()
		}
	}
}

func jsonResponse(w http.ResponseWriter, code int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}

func (s *UIServer) handleStartDaemon(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Check if daemon is already running
	client, err := s.getClient()
	if err == nil {
		client.Close()
		jsonResponse(w, http.StatusOK, map[string]any{
			"success": true,
			"message": "Daemon is already running",
		})
		return
	}

	// 2. Locate daemon executable
	daemonPath := findDaemonBinary()
	if daemonPath == "" {
		jsonResponse(w, http.StatusInternalServerError, map[string]any{
			"success": false,
			"error":   "Could not locate ant-daemon executable on disk",
		})
		return
	}

	security.Info("Requesting privileged elevation to launch daemon: %s", daemonPath)

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		// AppleScript system authorization prompt (Touch ID or password)
		script := fmt.Sprintf("do shell script %q with administrator privileges", daemonPath)
		cmd = exec.Command("osascript", "-e", script)
	case "windows":
		// Windows UAC elevation prompt
		psCmd := fmt.Sprintf("Start-Process -FilePath '%s' -Verb RunAs", daemonPath)
		cmd = exec.Command("powershell", "-NoProfile", "-Command", psCmd)
	case "linux":
		if _, err := exec.LookPath("pkexec"); err == nil {
			cmd = exec.Command("pkexec", daemonPath)
		} else {
			cmd = exec.Command("sudo", daemonPath)
		}
	default:
		jsonResponse(w, http.StatusInternalServerError, map[string]any{
			"success": false,
			"error":   "Unsupported platform for automated privilege escalation",
		})
		return
	}

	if err := cmd.Start(); err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]any{
			"success": false,
			"error":   fmt.Sprintf("Failed to launch elevation process: %v", err),
		})
		return
	}

	// 3. Poll IPC socket/port for up to 6 seconds for daemon to initialize
	deadline := time.Now().Add(6 * time.Second)
	var online bool
	for time.Now().Before(deadline) {
		time.Sleep(300 * time.Millisecond)
		if c, err := s.getClient(); err == nil {
			c.Close()
			online = true
			break
		}
	}

	if !online {
		jsonResponse(w, http.StatusOK, map[string]any{
			"success": false,
			"error":   "Elevation prompt was cancelled or daemon failed to bind IPC socket within 6s",
		})
		return
	}

	jsonResponse(w, http.StatusOK, map[string]any{
		"success": true,
		"message": "Daemon launched successfully",
	})
}

func findDaemonBinary() string {
	// 1. Next to the ant-ui executable (e.g. inside macOS .app Contents/MacOS)
	execPath, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(execPath)
		candidate := filepath.Join(dir, "ant-daemon")
		if runtime.GOOS == "windows" {
			candidate += ".exe"
		}
		if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() {
			return candidate
		}
	}

	// 2. Standard system location
	if runtime.GOOS != "windows" {
		candidate := "/usr/local/bin/ant-daemon"
		if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() {
			return candidate
		}
	}

	// 3. Current working directory bin/ paths or PATH lookup
	candidates := []string{
		"bin/ant-daemon",
		"bin/windows/ant-daemon.exe",
		"ant-daemon",
	}
	for _, c := range candidates {
		if path, err := exec.LookPath(c); err == nil {
			if abs, err := filepath.Abs(path); err == nil {
				return abs
			}
			return path
		}
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			if abs, err := filepath.Abs(c); err == nil {
				return abs
			}
			return c
		}
	}

	return ""
}

func openBrowser(url string) {
	switch runtime.GOOS {
	case "darwin":
		_ = exec.Command("open", url).Start()
	case "windows":
		_ = exec.Command("cmd", "/c", "start", url).Start()
	case "linux":
		_ = exec.Command("xdg-open", url).Start()
	}
}
