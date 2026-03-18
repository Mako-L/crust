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

const crustHookMarker = "evaluate-hook"

// hookConfig represents one hook configuration entry within a hook group.
type hookConfig struct {
	Type    string `json:"type"`
	Command string `json:"command"`
	Timeout int    `json:"timeout,omitempty"`
}

// hookGroup represents a group of hooks with an optional matcher.
// Claude Code settings.json schema:
//
//	{ "matcher": "...", "hooks": [{ "type": "command", "command": "...", "timeout": 5000 }] }
type hookGroup struct {
	Matcher string       `json:"matcher,omitempty"`
	Hooks   []hookConfig `json:"hooks"`
}

// claudeSettingsPath returns the path to ~/.claude/settings.json.
func claudeSettingsPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".claude", "settings.json")
}

// InstallClaudeHook installs a PreToolUse hook in ~/.claude/settings.json
// that routes tool call evaluation through the crust binary.
// The hook command calls "<crustBin> evaluate-hook".
// Idempotent: skips if a crust hook is already installed.
//
// Claude Code reads hooks from settings.json under the "hooks" key:
//
//	{
//	  "hooks": {
//	    "PreToolUse": [
//	      { "hooks": [{ "type": "command", "command": "...", "timeout": 5000 }] }
//	    ]
//	  }
//	}
func InstallClaudeHook(crustBin string) error {
	if crustBin == "" {
		return fmt.Errorf("crust binary path is empty")
	}

	settingsPath := claudeSettingsPath()
	if settingsPath == "" {
		return fmt.Errorf("cannot determine Claude settings path")
	}

	// Ensure ~/.claude/ directory exists.
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		return fmt.Errorf("create settings dir: %w", err)
	}

	// Read existing settings file (may not exist yet).
	// Use map[string]json.RawMessage to preserve all other keys.
	settings := make(map[string]json.RawMessage)
	data, err := os.ReadFile(settingsPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read settings: %w", err)
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &settings); err != nil {
			return fmt.Errorf("parse settings: %w", err)
		}
	}

	// Parse existing hooks section.
	var hooks map[string][]hookGroup
	if raw, ok := settings["hooks"]; ok {
		if err := json.Unmarshal(raw, &hooks); err != nil {
			return fmt.Errorf("parse hooks in settings: %w", err)
		}
	}
	if hooks == nil {
		hooks = make(map[string][]hookGroup)
	}

	// Check if crust hook already exists in any PreToolUse group.
	for _, group := range hooks["PreToolUse"] {
		for _, h := range group.Hooks {
			if strings.Contains(h.Command, crustHookMarker) {
				return nil // already installed
			}
		}
	}

	// Add crust hook as a new group (no matcher = applies to all tools).
	// Quote the binary path in case it contains spaces.
	cmd := fmt.Sprintf("%q evaluate-hook", crustBin)
	hooks["PreToolUse"] = append(hooks["PreToolUse"], hookGroup{
		Hooks: []hookConfig{{
			Type:    "command",
			Command: cmd,
			Timeout: 5000,
		}},
	})

	// Write hooks back into settings.
	hooksRaw, err := json.Marshal(hooks)
	if err != nil {
		return fmt.Errorf("marshal hooks: %w", err)
	}
	settings["hooks"] = hooksRaw

	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal settings: %w", err)
	}
	return fileutil.SecureWriteFile(settingsPath, append(out, '\n'))
}

// UninstallClaudeHook removes crust entries from ~/.claude/settings.json hooks.
// No-op if the file doesn't exist or has no crust hooks.
func UninstallClaudeHook() error {
	settingsPath := claudeSettingsPath()
	if settingsPath == "" {
		return nil
	}

	data, err := os.ReadFile(settingsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read settings: %w", err)
	}

	// Preserve all other settings keys.
	settings := make(map[string]json.RawMessage)
	if err := json.Unmarshal(data, &settings); err != nil {
		return fmt.Errorf("parse settings: %w", err)
	}

	raw, ok := settings["hooks"]
	if !ok {
		return nil // no hooks section
	}

	var hooks map[string][]hookGroup
	if err := json.Unmarshal(raw, &hooks); err != nil {
		return fmt.Errorf("parse hooks: %w", err)
	}

	// Filter out crust hooks from PreToolUse groups.
	groups := hooks["PreToolUse"]
	var filtered []hookGroup
	for _, group := range groups {
		var cleanHooks []hookConfig
		for _, h := range group.Hooks {
			if !strings.Contains(h.Command, crustHookMarker) {
				cleanHooks = append(cleanHooks, h)
			}
		}
		if len(cleanHooks) > 0 {
			group.Hooks = cleanHooks
			filtered = append(filtered, group)
		}
	}

	if len(filtered) == len(groups) {
		return nil // nothing to remove
	}

	if len(filtered) == 0 {
		delete(hooks, "PreToolUse")
	} else {
		hooks["PreToolUse"] = filtered
	}

	// If hooks map is now empty, remove the key from settings.
	if len(hooks) == 0 {
		delete(settings, "hooks")
	} else {
		hooksRaw, err := json.Marshal(hooks)
		if err != nil {
			return fmt.Errorf("marshal hooks: %w", err)
		}
		settings["hooks"] = hooksRaw
	}

	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal settings: %w", err)
	}
	return fileutil.SecureWriteFile(settingsPath, append(out, '\n'))
}

// cleanupStaleHooksFile removes the old ~/.claude/hooks.json if it exists
// and only contains crust hooks. This cleans up after the bug where hooks
// were written to the wrong file.
func cleanupStaleHooksFile() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	stale := filepath.Join(home, ".claude", "hooks.json")
	data, err := os.ReadFile(stale)
	if err != nil {
		return // doesn't exist or unreadable
	}

	// Only remove if the file contains just crust hooks.
	var hf struct {
		Hooks map[string][]struct {
			Command string `json:"command"`
		} `json:"hooks"`
	}
	if json.Unmarshal(data, &hf) != nil {
		return
	}

	// Check all entries — if any are NOT crust hooks, leave the file.
	for _, entries := range hf.Hooks {
		for _, e := range entries {
			if !strings.Contains(e.Command, crustHookMarker) {
				return // has non-crust hooks, don't delete
			}
		}
	}

	_ = os.Remove(stale)
}
