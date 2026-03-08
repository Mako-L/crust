# Plugin System

## Overview

Plugins are **late-stage protection layers** that run after the built-in 13-step evaluation pipeline. When the engine determines a tool call is allowed, it passes the call through registered plugins before returning the final verdict. The first plugin to return a non-nil result blocks the call.

```text
Tool Call ──▶ [Steps 0-12: Built-in Pipeline] ──▶ allowed? ──▶ [Step 13: Plugins] ──▶ Final Verdict
                                                     │                  │
                                                  ↓ BLOCK           ↓ BLOCK
                                              (built-in)         (plugin)
```

Plugins are general-purpose — they can implement sandboxing, rate limiting, audit logging, custom policy enforcement, or any other protection logic. They receive the same extracted information that the built-in pipeline computed (paths, hosts, operations, commands), plus a **read-only snapshot of all active engine rules**.

Plugins communicate over a **JSON wire protocol** (newline-delimited JSON over stdin/stdout). This means plugins can be written in **any language** — Go, Python, Rust, Node.js, etc. The engine spawns plugin processes at startup and communicates via IPC. This also provides **OS-level crash isolation**: a plugin segfault cannot crash the engine.

---

## Wire Protocol

Plugins are external processes. Communication is **newline-delimited JSON** over stdin/stdout (one JSON object per line, each direction):

```text
crust ──stdin──▶  plugin process  ──stdout──▶ crust
       (requests)                  (responses)
```

Stderr is passed through for plugin diagnostics.

### Message Format

Request (crust → plugin):
```json
{"method": "<method>", "params": <JSON>}
```

Response (plugin → crust):
```json
{"result": <JSON>}
```

or on error:
```json
{"error": "<message>"}
```

### Lifecycle

```text
1. crust spawns plugin process
2. crust → {"method":"init","params":{"name":"sandbox","config":{...}}}
3. plugin → {"result":"ok"}
4. crust → {"method":"evaluate","params":{...}}    ← repeated per tool call
5. plugin → {"result":null}                         ← allow
   plugin → {"result":{"rule_name":"...","severity":"high","message":"..."}}  ← block
6. crust → {"method":"close"}
7. plugin → {"result":"ok"}
8. plugin exits
```

### Methods

| Method | Params | Response | Description |
|--------|--------|----------|-------------|
| `init` | `InitParams` | `"ok"` or error | One-time setup with plugin config |
| `evaluate` | `Request` | `null` (allow) or `Result` (block) | Evaluate a tool call |
| `close` | none | `"ok"` | Graceful shutdown |

---

## Data Types

### Request

Sent with `method="evaluate"`. Contains everything the engine extracted during steps 0-12, plus a snapshot of all active rules:

```json
{
    "tool_name": "Bash",
    "arguments": {"command": "rm -rf /etc"},
    "operation": "execute",
    "operations": ["execute", "delete"],
    "command": "rm -rf /etc",
    "paths": ["/etc"],
    "hosts": [],
    "content": "{\"command\":\"rm -rf /etc\"}",
    "evasive": false,
    "rules": [
        {
            "name": "protect-etc",
            "description": "Block /etc modifications",
            "source": "builtin",
            "severity": "critical",
            "priority": 10,
            "actions": ["read", "write", "delete"],
            "block_paths": ["/etc/**"],
            "block_except": ["/etc/hostname"],
            "message": "Cannot modify system files",
            "locked": true,
            "enabled": true,
            "hit_count": 42
        }
    ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `tool_name` | string | Sanitized tool name (e.g. "Bash", "Read", "Write") |
| `arguments` | object | Raw JSON arguments from the tool call |
| `operation` | string | Primary operation: `read`, `write`, `delete`, `copy`, `move`, `execute`, `network` |
| `operations` | string[] | All operations (a command may both read and write) |
| `command` | string | Raw shell command (Bash tool only) |
| `paths` | string[] | Normalized + symlink-resolved paths |
| `hosts` | string[] | Extracted hostnames/IPs |
| `content` | string | Write content or full raw JSON of all arguments |
| `evasive` | bool | True if command uses shell tricks that prevent static analysis |
| `rules` | RuleSnapshot[] | Read-only snapshot of all active engine rules |

### RuleSnapshot

Each element in `rules` describes one engine rule:

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Rule identifier (e.g. "protect-ssh-keys") |
| `description` | string | Human-readable description |
| `source` | string | `"builtin"`, `"user"`, or `"cli"` |
| `severity` | string | `"critical"`, `"high"`, `"warning"`, `"info"` |
| `priority` | int | Lower = higher priority (default 50) |
| `actions` | string[] | Operations this rule applies to |
| `block_paths` | string[] | Glob patterns this rule blocks |
| `block_except` | string[] | Exception patterns |
| `block_hosts` | string[] | Host patterns for network rules |
| `message` | string | Block message shown to the user |
| `locked` | bool | True if rule survives `--disable-builtin` |
| `enabled` | bool | True if rule is active |
| `hit_count` | int | Times this rule has matched |

Plugins can use the rule snapshot for context-aware decisions, such as:
- Checking if a path is already protected by a builtin rule
- Enforcing policy that certain rules must exist (compliance)
- Adjusting severity based on what protections are already active

### Result

Returned to block a tool call. Return `null` to allow.

```json
{
    "rule_name": "sandbox:fs-deny",
    "severity": "high",
    "action": "block",
    "message": "path /etc is outside sandbox"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `rule_name` | string | Plugin-namespaced rule (e.g. "sandbox:fs-deny") |
| `severity` | string | `"critical"`, `"high"`, `"warning"`, `"info"` (invalid defaults to `"high"`) |
| `action` | string | `"block"` (default), `"log"`, or `"alert"` |
| `message` | string | Human-readable reason |

The `plugin` field is auto-filled by the registry — plugins don't need to set it.

### InitParams

Sent with `method="init"`:

```json
{
    "name": "sandbox",
    "config": {"allowed_dirs": ["/home/user/project"], "deny_net": true}
}
```

---

## Crash Isolation

### Worker Pool

Each plugin evaluation runs in a **pooled goroutine** with `recover()` and a context-based timeout. This isolates the engine from both in-process panics and external process crashes.

```text
Engine.Evaluate()
  │
  ▼
Registry.Evaluate(ctx, req)
  │
  ├─▶ acquire slot from pool (with context timeout — no indefinite blocking)
  │     │
  │     ▼
  │   goroutine {
  │     defer recover()           ← catches in-process panics
  │     ctx with timeout          ← passed to plugin for cooperative cancellation
  │     result = plugin.Evaluate(ctx, req)
  │   }
  │     │
  │     ├─▶ result received       → return result
  │     ├─▶ panic / crash         → log (with stack trace), increment failure count, skip plugin
  │     ├─▶ timeout exceeded      → log, increment failure count, skip plugin
  │     └─▶ pool exhausted        → log, skip plugin (NOT counted as plugin failure)
  │
  ├─▶ next plugin ...
  │
  └─▶ all plugins passed → return nil (allowed)
```

The pool uses a **counting semaphore** pattern (buffered channel). Slot acquisition respects the caller's context — no indefinite blocking. Default pool size: `min(GOMAXPROCS, 8)`. Default timeout: 5 seconds.

**Pool exhaustion** (all slots busy) is not the plugin's fault — it does not increment the circuit breaker failure counter. Only panics and timeouts count as plugin failures.

### Circuit Breaker

A plugin that fails repeatedly is **automatically disabled** with exponential backoff:

```text
  ┌─────────┐  3 consecutive    ┌──────────┐  cooldown elapsed   ┌─────────┐
  │ Healthy │ ── failures ────▶ │ Disabled │ ── (backoff) ─────▶ │ Retry   │
  │         │ ◀── success ───── │          │                      │         │
  └─────────┘   (reset count)   └──────────┘                      └─────────┘
                                      ▲                                │
                                      └──── fails again ───────────────┘
                                            (double cooldown)

After 5 disable cycles → Permanently Disabled
```

| Parameter | Value | Description |
|-----------|-------|-------------|
| Max consecutive failures | 3 | Disable after 3 panics/timeouts in a row |
| Base cooldown | 5 minutes | First disable cycle |
| Backoff | 2x per cycle | 5min → 10min → 20min → 40min → 1hr (cap) |
| Max disable cycles | 5 | After 5 cycles, permanently disabled |

Circuit breaker state transitions are **mutex-protected** to prevent TOCTOU races under concurrent evaluation. Plugin names are **cached at registration** to prevent spoofing via dynamic `Name()` returns. Each plugin gets a **deep copy** of the request to prevent mutation across plugins.

---

## Go Interface

For Go-based plugins (in-process or as the `ProcessPlugin` adapter), the interface is:

```go
package plugin

type Plugin interface {
    Name() string
    Init(cfg json.RawMessage) error
    Evaluate(ctx context.Context, req Request) *Result
    Close() error
}
```

The `ProcessPlugin` adapter implements this interface by spawning an external process and communicating over the wire protocol:

```go
// Launch a Python plugin
p := plugin.NewProcessPlugin("sandbox", "/usr/bin/python3", "sandbox_plugin.py")
registry.Register(p, json.RawMessage(`{"allowed_dirs":["/home/user/project"]}`))
```

### Auto-Restart

If a `ProcessPlugin`'s external process crashes or times out during IPC, it is killed and **automatically restarted** on the next `Evaluate` call (up to 3 consecutive restart failures). The init configuration is saved at startup and replayed on restart. Closing stdout on kill unblocks any goroutine waiting on the scanner, preventing goroutine leaks.

---

## Engine Integration

The engine holds a `*plugin.Registry` and calls it as step 13:

```go
func (e *Engine) Evaluate(call ToolCall) MatchResult {
    // Steps 0-12: existing pipeline ...
    result := e.matchRules(&info, allPaths, call.Name)
    if result.Matched {
        return result  // built-in blocked — skip plugins
    }

    // Step 13: Plugin evaluation (post-pipeline).
    if e.plugins != nil {
        if pr := e.plugins.Evaluate(ctx, plugin.Request{
            ToolName:   call.Name,
            Arguments:  call.Arguments,
            Operation:  string(info.Operation),
            Operations: operationsToStrings(info.Operations),
            Command:    info.Command,
            Paths:      allPaths,
            Hosts:      info.Hosts,
            Content:    cmp.Or(info.RawJSON, info.Content),
            Rules:      e.ruleSnapshots(),  // current rule snapshot
        }); pr != nil {
            return NewMatch(
                pr.RuleName,
                Severity(pr.EffectiveSeverity()),
                Action(pr.EffectiveAction()),
                pr.Message,
            )
        }
    }

    return result  // allowed
}
```

---

## Example: Sandbox Plugin (Python)

A filesystem sandbox plugin in Python, communicating over the wire protocol:

```python
#!/usr/bin/env python3
"""Sandbox plugin for crust — restricts file access to allowed directories."""

import json
import sys
import os

allowed_dirs = []
deny_net = False

def handle_init(params):
    global allowed_dirs, deny_net
    config = params.get("config") or {}
    allowed_dirs = config.get("allowed_dirs", [])
    deny_net = config.get("deny_net", False)
    return "ok"

def handle_evaluate(req):
    # Block network if configured
    if deny_net and req.get("operation") == "network":
        return {
            "rule_name": "sandbox:net-deny",
            "severity": "high",
            "message": "network access denied by sandbox policy",
        }

    # Check paths against allowed directories
    for path in req.get("paths", []):
        if not is_allowed(path):
            return {
                "rule_name": "sandbox:fs-deny",
                "severity": "high",
                "message": f"path {path} is outside sandbox",
            }

    # Example: use rule snapshot to check if path is already protected
    for rule in req.get("rules", []):
        if not rule.get("enabled"):
            return {
                "rule_name": "sandbox:disabled-rule",
                "severity": "warning",
                "message": f"rule {rule['name']} is disabled — sandbox requires it",
            }

    return None  # allow

def is_allowed(path):
    if not allowed_dirs:
        return True
    path = os.path.realpath(path)
    return any(
        os.path.commonpath([d, path]) == os.path.realpath(d)
        for d in allowed_dirs
    )

def main():
    for line in sys.stdin:
        msg = json.loads(line)
        method = msg["method"]
        params = msg.get("params")

        if method == "init":
            result = handle_init(params)
        elif method == "evaluate":
            result = handle_evaluate(params)
        elif method == "close":
            result = "ok"
        else:
            print(json.dumps({"error": f"unknown method: {method}"}), flush=True)
            continue

        print(json.dumps({"result": result}), flush=True)

        if method == "close":
            break

if __name__ == "__main__":
    main()
```

---

## Example: Rate Limiter Plugin (Go, in-process)

```go
package ratelimit

import (
    "context"
    "encoding/json"
    "fmt"
    "sync"
    "time"

    "github.com/BakeLens/crust/internal/plugin"
)

type Config struct {
    MaxPerMinute int `json:"max_per_minute"` // 0 = unlimited
}

type RateLimiter struct {
    config Config
    mu     sync.Mutex
    window []time.Time
}

func New() plugin.Plugin { return &RateLimiter{} }

func (r *RateLimiter) Name() string { return "rate-limiter" }

func (r *RateLimiter) Init(cfg json.RawMessage) error {
    if cfg != nil {
        return json.Unmarshal(cfg, &r.config)
    }
    return nil
}

func (r *RateLimiter) Evaluate(_ context.Context, req plugin.Request) *plugin.Result {
    if r.config.MaxPerMinute <= 0 {
        return nil
    }

    r.mu.Lock()
    defer r.mu.Unlock()

    now := time.Now()
    cutoff := now.Add(-time.Minute)

    // Trim expired entries
    i := 0
    for i < len(r.window) && r.window[i].Before(cutoff) {
        i++
    }
    r.window = r.window[i:]

    if len(r.window) >= r.config.MaxPerMinute {
        return &plugin.Result{
            RuleName: "ratelimit:exceeded",
            Severity: "warning",
            Message:  fmt.Sprintf("rate limit exceeded: %d calls/min", r.config.MaxPerMinute),
        }
    }

    r.window = append(r.window, now)
    return nil
}

func (r *RateLimiter) Close() error { return nil }
```

---

## Design Principles

1. **Wire protocol first** — Plugins are external processes communicating over JSON stdin/stdout. Any language can implement a plugin. The Go `Plugin` interface is an internal adapter, not the primary API.

2. **Late-stage only** — Plugins never weaken built-in protections. They run after all 13 built-in steps pass. A plugin can only block, never allow something the engine blocked.

3. **First-block wins** — Plugins are evaluated in registration order. The first non-nil Result short-circuits evaluation.

4. **OS-level crash isolation** — External plugins run as separate processes. A segfault, memory leak, or infinite loop in a plugin cannot crash the engine. The worker pool adds goroutine-level isolation with `recover()` + timeout on top.

5. **Circuit breaker with exponential backoff** — A plugin that fails 3 consecutive times is disabled with exponential backoff (5min → 10min → ... → 1hr). After 5 disable cycles, permanently disabled. Prevents buggy plugins from burning resources.

6. **Rule snapshot access** — Plugins receive a read-only snapshot of all active engine rules. This enables context-aware decisions: "is this path already protected?", "are required rules enabled?", "what's the current hit count?"

7. **No internal type leakage** — `Request` and `Result` use plain JSON types (`string`, `int`, `bool`), not Go-specific types. This keeps the wire protocol stable and language-agnostic.

8. **Validated results** — Invalid severity values default to `"high"`. Empty action defaults to `"block"`. Plugin names are cached at registration to prevent spoofing. Request data is deep-copied per plugin to prevent mutation.

9. **Clean lifecycle** — `init` is called once at startup. `close` is called in reverse order during shutdown. The registry rejects new evaluations after close begins.

---

## Future Extensions

The wire protocol is designed to support future additions without breaking existing plugins. Unknown fields in JSON are silently ignored by well-behaved parsers.

| Extension | How |
|-----------|-----|
| **Plugin ordering** | Add `priority` field to init response — registry sorts by priority |
| **Config reload** | New method `reload` with updated config — hot-reload without restart |
| **Bidirectional plugins** | Add `direction` field to Request (`"request"` / `"response"`) for MCP/ACP response scanning |
| **Plugin metrics** | Registry tracks per-plugin call count, block count, latency (exposed via `Stats()`) |
| **Health check** | New method `health` — registry probes periodically to detect stuck processes |
