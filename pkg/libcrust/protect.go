//go:build libcrust

package libcrust

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"

	"github.com/BakeLens/crust/internal/daemon"
	"github.com/BakeLens/crust/internal/daemon/registry"
)

// protectState tracks the auto-protect lifecycle.
var protect struct {
	mu      sync.Mutex
	running bool
	port    int
}

// StartProtect starts the full protection stack:
// 1. Starts HTTP proxy in auto mode on an auto-assigned port
// 2. Patches all registered agent configs (HTTP URL + MCP wrapping)
// Returns the proxy port, or error.
func StartProtect() (int, error) {
	protect.mu.Lock()
	defer protect.mu.Unlock()

	if protect.running {
		return protect.port, nil
	}

	// Start proxy in auto mode (port 0 = auto-assign, empty upstream = auto mode).
	if err := StartProxy(0, "", "", ""); err != nil {
		return 0, fmt.Errorf("start proxy: %w", err)
	}

	// Get the assigned port.
	addr := ProxyAddress()
	if addr == "" {
		StopProxy()
		return 0, fmt.Errorf("proxy started but address is empty")
	}
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		StopProxy()
		return 0, fmt.Errorf("parse proxy address %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		StopProxy()
		return 0, fmt.Errorf("parse port %q: %w", portStr, err)
	}

	// Patch all agent configs to route through the proxy.
	daemon.PatchAgentConfigs(port)

	// Install Claude Code PreToolUse hook for direct tool call interception.
	crustBin := daemon.ResolveCrustBin()
	if crustBin != "" {
		if err := InstallClaudeHook(crustBin); err != nil {
			// Non-fatal: Claude Code hooks are supplementary protection.
			fmt.Fprintf(os.Stderr, "crust: install claude hook: %v\n", err)
		}
	}

	protect.running = true
	protect.port = port
	return port, nil
}

// StopProtect tears down the full protection stack:
// 1. Restores all patched agent configs
// 2. Stops the HTTP proxy
func StopProtect() {
	protect.mu.Lock()
	defer protect.mu.Unlock()

	if !protect.running {
		return
	}

	// Remove Claude Code hooks.
	if err := UninstallClaudeHook(); err != nil {
		fmt.Fprintf(os.Stderr, "crust: uninstall claude hook: %v\n", err)
	}

	daemon.RestoreAgentConfigs()
	StopProxy()
	protect.running = false
	protect.port = 0
}

// ProtectPort returns the proxy port, or 0 if not running.
func ProtectPort() int {
	protect.mu.Lock()
	defer protect.mu.Unlock()
	return protect.port
}

// ProtectStatus returns the current protection status as JSON.
func ProtectStatus() string {
	protect.mu.Lock()
	port := protect.port
	running := protect.running
	protect.mu.Unlock()

	// Get list of patched agents from registry.
	var patched []string
	for _, t := range registry.Default.Targets() {
		if registry.Default.IsPatched(t.Name()) {
			patched = append(patched, t.Name())
		}
	}
	if patched == nil {
		patched = []string{}
	}

	status := map[string]any{
		"active":         running,
		"proxy_port":     port,
		"patched_agents": patched,
	}
	out, _ := json.Marshal(status)
	return string(out)
}

// ListAgents returns a JSON array of all registered agents with their status.
func ListAgents() string {
	type agentInfo struct {
		Name    string `json:"name"`
		Patched bool   `json:"patched"`
	}
	var agents []agentInfo
	for _, t := range registry.Default.Targets() {
		agents = append(agents, agentInfo{
			Name:    t.Name(),
			Patched: registry.Default.IsPatched(t.Name()),
		})
	}
	if agents == nil {
		agents = []agentInfo{}
	}
	out, _ := json.Marshal(agents)
	return string(out)
}

// EnableAgent patches a single agent by name.
func EnableAgent(name string) error {
	protect.mu.Lock()
	port := protect.port
	protect.mu.Unlock()

	crustBin := daemon.ResolveCrustBin()
	for _, t := range registry.Default.Targets() {
		if t.Name() == name {
			return t.Patch(port, crustBin)
		}
	}
	return fmt.Errorf("agent %q not found", name)
}

// DisableAgent restores a single agent by name.
func DisableAgent(name string) error {
	for _, t := range registry.Default.Targets() {
		if t.Name() == name {
			return t.Restore()
		}
	}
	return fmt.Errorf("agent %q not found", name)
}
