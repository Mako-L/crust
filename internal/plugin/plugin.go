package plugin

import (
	"context"
	"encoding/json"
	"slices"
)

// Plugin is a late-stage protection layer (step 13+).
// Runs only for tool calls that passed all built-in checks.
// Implementations must be safe for concurrent use.
type Plugin interface {
	// Name returns a unique identifier (e.g. "sandbox", "rate-limiter").
	Name() string

	// Init is called once when the plugin is registered.
	// cfg is plugin-specific JSON configuration; nil means use defaults.
	Init(cfg json.RawMessage) error

	// Evaluate inspects an allowed tool call.
	// Return nil to allow, non-nil to block.
	// Must be safe for concurrent calls.
	// The context carries the per-call timeout — plugins should respect ctx.Done().
	Evaluate(ctx context.Context, req Request) *Result

	// Close releases plugin resources (processes, connections, etc).
	Close() error
}

// Request is the data available to plugins.
// All fields are read-only deep copies — safe for concurrent use.
// Serialized as JSON over the wire protocol for external plugins.
type Request struct {
	ToolName   string          `json:"tool_name"`
	Arguments  json.RawMessage `json:"arguments"`
	Operation  string          `json:"operation"`
	Operations []string        `json:"operations"`
	Command    string          `json:"command"`
	Paths      []string        `json:"paths"`
	Hosts      []string        `json:"hosts"`
	Content    string          `json:"content"`
	Evasive    bool            `json:"evasive,omitempty"`

	// Rules is a snapshot of all active engine rules at evaluation time.
	// Plugins can use this for context-aware decisions (e.g., "is this path
	// already protected by a builtin rule?"). Read-only; plugins cannot
	// modify the engine's rules.
	Rules []RuleSnapshot `json:"rules,omitempty"`
}

// RuleSnapshot is a read-only, JSON-safe view of an engine rule.
// It contains everything a plugin needs without leaking internal types.
type RuleSnapshot struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Source      string   `json:"source"` // "builtin", "user", "cli"
	Severity    string   `json:"severity"`
	Priority    int      `json:"priority"`
	Actions     []string `json:"actions"`               // "read", "write", "delete", "execute", "network", ...
	BlockPaths  []string `json:"block_paths,omitempty"` // glob patterns
	BlockExcept []string `json:"block_except,omitempty"`
	BlockHosts  []string `json:"block_hosts,omitempty"`
	Message     string   `json:"message"`
	Locked      bool     `json:"locked"`
	Enabled     bool     `json:"enabled"`
	HitCount    int64    `json:"hit_count"`
}

// DeepCopy returns a copy of the request with all slices cloned.
// Prevents a plugin from mutating data seen by subsequent plugins.
func (r Request) DeepCopy() Request {
	cp := r
	cp.Arguments = slices.Clone(r.Arguments)
	cp.Operations = slices.Clone(r.Operations)
	cp.Paths = slices.Clone(r.Paths)
	cp.Hosts = slices.Clone(r.Hosts)
	cp.Rules = slices.Clone(r.Rules)
	return cp
}

// Result describes why a plugin blocked a call.
// Return nil from Evaluate to allow the call.
type Result struct {
	Plugin   string `json:"plugin"`
	RuleName string `json:"rule_name"`
	Severity string `json:"severity"`
	Action   string `json:"action,omitempty"` // block (default), log, alert
	Message  string `json:"message"`
}

// ValidSeverities is the set of accepted severity values.
var ValidSeverities = map[string]bool{
	"critical": true,
	"high":     true,
	"warning":  true,
	"info":     true,
}

// ValidActions is the set of accepted action values.
var ValidActions = map[string]bool{
	"block": true,
	"log":   true,
	"alert": true,
	"":      true, // empty defaults to "block"
}

// EffectiveAction returns the action, defaulting to "block" if empty.
func (r *Result) EffectiveAction() string {
	if r.Action == "" {
		return "block"
	}
	return r.Action
}

// EffectiveSeverity returns the severity, defaulting to "high" if invalid.
func (r *Result) EffectiveSeverity() string {
	if ValidSeverities[r.Severity] {
		return r.Severity
	}
	return "high"
}
