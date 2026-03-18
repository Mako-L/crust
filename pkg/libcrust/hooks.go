//go:build libcrust

package libcrust

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BakeLens/crust/internal/fileutil"
)

const crustHookMarker = "crust-app evaluate-hook"

// hooksFile represents the structure of ~/.claude/hooks.json.
type hooksFile struct {
	Hooks map[string][]hookEntry `json:"hooks"`
}

type hookEntry struct {
	Type    string `json:"type"`
	Command string `json:"command"`
	Timeout int    `json:"timeout,omitempty"`
}

// claudeHooksPath returns the path to ~/.claude/hooks.json.
func claudeHooksPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".claude", "hooks.json")
}

// InstallClaudeHook installs a PreToolUse hook in ~/.claude/hooks.json
// that routes tool call evaluation through the crust binary.
// The hook command calls "<crustBin> evaluate-hook".
// Idempotent: skips if a crust hook is already installed.
func InstallClaudeHook(crustBin string) error {
	if crustBin == "" {
		return fmt.Errorf("crust binary path is empty")
	}

	hooksPath := claudeHooksPath()
	if hooksPath == "" {
		return fmt.Errorf("cannot determine Claude hooks path")
	}

	// Ensure ~/.claude/ directory exists.
	if err := os.MkdirAll(filepath.Dir(hooksPath), 0o700); err != nil {
		return fmt.Errorf("create hooks dir: %w", err)
	}

	// Read existing hooks file (may not exist yet).
	var hf hooksFile
	data, err := os.ReadFile(hooksPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read hooks: %w", err)
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &hf); err != nil {
			return fmt.Errorf("parse hooks: %w", err)
		}
	}
	if hf.Hooks == nil {
		hf.Hooks = make(map[string][]hookEntry)
	}

	// Check if crust hook already exists.
	for _, h := range hf.Hooks["PreToolUse"] {
		if strings.Contains(h.Command, crustHookMarker) {
			return nil // already installed
		}
	}

	// Add crust hook.
	// Quote the binary path in case it contains spaces.
	cmd := fmt.Sprintf("%q evaluate-hook", crustBin)
	hf.Hooks["PreToolUse"] = append(hf.Hooks["PreToolUse"], hookEntry{
		Type:    "command",
		Command: cmd,
		Timeout: 5000,
	})

	out, err := json.MarshalIndent(hf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal hooks: %w", err)
	}
	return fileutil.SecureWriteFile(hooksPath, append(out, '\n'))
}

// UninstallClaudeHook removes crust entries from ~/.claude/hooks.json.
// No-op if the file doesn't exist or has no crust hooks.
func UninstallClaudeHook() error {
	hooksPath := claudeHooksPath()
	if hooksPath == "" {
		return nil
	}

	data, err := os.ReadFile(hooksPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read hooks: %w", err)
	}

	var hf hooksFile
	if err := json.Unmarshal(data, &hf); err != nil {
		return fmt.Errorf("parse hooks: %w", err)
	}

	// Filter out crust hooks from PreToolUse.
	entries := hf.Hooks["PreToolUse"]
	filtered := make([]hookEntry, 0, len(entries))
	for _, h := range entries {
		if !strings.Contains(h.Command, crustHookMarker) {
			filtered = append(filtered, h)
		}
	}

	if len(filtered) == len(entries) {
		return nil // nothing to remove
	}

	if len(filtered) == 0 {
		delete(hf.Hooks, "PreToolUse")
	} else {
		hf.Hooks["PreToolUse"] = filtered
	}

	// If hooks map is now empty, remove the file entirely.
	if len(hf.Hooks) == 0 {
		return os.Remove(hooksPath)
	}

	out, err := json.MarshalIndent(hf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal hooks: %w", err)
	}
	return fileutil.SecureWriteFile(hooksPath, append(out, '\n'))
}
