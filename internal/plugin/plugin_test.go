package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// =============================================================================
// Test helpers — mock plugins
// =============================================================================

// allowPlugin always allows.
type allowPlugin struct{ name string }

func (p *allowPlugin) Name() string                              { return p.name }
func (p *allowPlugin) Init(json.RawMessage) error                { return nil }
func (p *allowPlugin) Evaluate(context.Context, Request) *Result { return nil }
func (p *allowPlugin) Close() error                              { return nil }

// blockPlugin always blocks with the given result.
type blockPlugin struct {
	name   string
	result Result
}

func (p *blockPlugin) Name() string               { return p.name }
func (p *blockPlugin) Init(json.RawMessage) error { return nil }
func (p *blockPlugin) Evaluate(_ context.Context, _ Request) *Result {
	r := p.result
	return &r
}
func (p *blockPlugin) Close() error { return nil }

// panicPlugin panics on every Evaluate call.
type panicPlugin struct{ name string }

func (p *panicPlugin) Name() string                              { return p.name }
func (p *panicPlugin) Init(json.RawMessage) error                { return nil }
func (p *panicPlugin) Evaluate(context.Context, Request) *Result { panic("intentional panic") }
func (p *panicPlugin) Close() error                              { return nil }

// hangPlugin blocks until context is canceled.
type hangPlugin struct{ name string }

func (p *hangPlugin) Name() string               { return p.name }
func (p *hangPlugin) Init(json.RawMessage) error { return nil }
func (p *hangPlugin) Close() error               { return nil }
func (p *hangPlugin) Evaluate(ctx context.Context, _ Request) *Result {
	<-ctx.Done() // block until timeout
	return nil
}

// countPlugin counts Evaluate calls.
type countPlugin struct {
	name  string
	calls atomic.Int64
}

func (p *countPlugin) Name() string               { return p.name }
func (p *countPlugin) Init(json.RawMessage) error { return nil }
func (p *countPlugin) Close() error               { return nil }
func (p *countPlugin) Evaluate(_ context.Context, _ Request) *Result {
	p.calls.Add(1)
	return nil
}

// mutatingPlugin tries to mutate the request (for Bug 6.4 test).
type mutatingPlugin struct{ name string }

func (p *mutatingPlugin) Name() string               { return p.name }
func (p *mutatingPlugin) Init(json.RawMessage) error { return nil }
func (p *mutatingPlugin) Close() error               { return nil }
func (p *mutatingPlugin) Evaluate(_ context.Context, req Request) *Result {
	if len(req.Paths) > 0 {
		req.Paths[0] = "/etc/shadow" // try to corrupt
	}
	if len(req.Hosts) > 0 {
		req.Hosts[0] = "evil.com"
	}
	if len(req.Rules) > 0 {
		req.Rules[0].Name = "corrupted" // try to corrupt rule snapshot
	}
	return nil
}

// initFailPlugin fails Init.
type initFailPlugin struct{ name string }

func (p *initFailPlugin) Name() string                              { return p.name }
func (p *initFailPlugin) Init(json.RawMessage) error                { return errors.New("init failed") }
func (p *initFailPlugin) Evaluate(context.Context, Request) *Result { return nil }
func (p *initFailPlugin) Close() error                              { return nil }

// dynamicNamePlugin returns different names — for Bug 6.2 test.
type dynamicNamePlugin struct {
	calls atomic.Int64
}

func (p *dynamicNamePlugin) Name() string {
	n := p.calls.Add(1)
	return fmt.Sprintf("dynamic-%d", n)
}
func (p *dynamicNamePlugin) Init(json.RawMessage) error { return nil }
func (p *dynamicNamePlugin) Evaluate(_ context.Context, _ Request) *Result {
	return &Result{RuleName: "test", Severity: "high", Message: "blocked"}
}
func (p *dynamicNamePlugin) Close() error { return nil }

// ruleAwarePlugin checks rules in the request and blocks if a specific rule exists.
type ruleAwarePlugin struct {
	name         string
	requiredRule string // block if this rule is NOT present
}

func (p *ruleAwarePlugin) Name() string               { return p.name }
func (p *ruleAwarePlugin) Init(json.RawMessage) error { return nil }
func (p *ruleAwarePlugin) Close() error               { return nil }
func (p *ruleAwarePlugin) Evaluate(_ context.Context, req Request) *Result {
	for _, r := range req.Rules {
		if r.Name == p.requiredRule {
			return nil // rule exists, allow
		}
	}
	return &Result{
		RuleName: p.name + ":missing-rule",
		Severity: "high",
		Message:  fmt.Sprintf("required rule %q not found in snapshot (%d rules)", p.requiredRule, len(req.Rules)),
	}
}

// inspectPlugin records the request it received.
type inspectPlugin struct {
	name  string
	store *atomic.Value
}

func (p *inspectPlugin) Name() string               { return p.name }
func (p *inspectPlugin) Init(json.RawMessage) error { return nil }
func (p *inspectPlugin) Close() error               { return nil }
func (p *inspectPlugin) Evaluate(_ context.Context, req Request) *Result {
	p.store.Store(req)
	return nil
}

// conditionalPlugin panics until failCount >= threshold, then returns nil.
type conditionalPlugin struct {
	name      string
	failCount *atomic.Int64
	threshold int64
}

func (p *conditionalPlugin) Name() string               { return p.name }
func (p *conditionalPlugin) Init(json.RawMessage) error { return nil }
func (p *conditionalPlugin) Close() error               { return nil }
func (p *conditionalPlugin) Evaluate(_ context.Context, _ Request) *Result {
	if p.failCount.Add(1) <= p.threshold {
		panic("conditional panic")
	}
	return nil
}

// =============================================================================
// Request / Result type tests
// =============================================================================

func TestRequest_DeepCopy(t *testing.T) {
	original := Request{
		ToolName:   "Bash",
		Arguments:  json.RawMessage(`{"command":"ls"}`),
		Operation:  "execute",
		Operations: []string{"execute", "read"},
		Paths:      []string{"/home/user/project"},
		Hosts:      []string{"example.com"},
		Content:    "test content",
		Rules: []RuleSnapshot{
			{Name: "rule1", Source: "builtin", Severity: "critical"},
		},
	}

	cp := original.DeepCopy()

	// Mutate the copy.
	cp.Paths[0] = "/etc/shadow"
	cp.Hosts[0] = "evil.com"
	cp.Operations[0] = "delete"
	cp.Arguments[0] = 'X'
	cp.Rules[0].Name = "corrupted"

	// Original must be unchanged.
	if original.Paths[0] != "/home/user/project" {
		t.Errorf("DeepCopy failed: original Paths mutated: %v", original.Paths)
	}
	if original.Hosts[0] != "example.com" {
		t.Errorf("DeepCopy failed: original Hosts mutated: %v", original.Hosts)
	}
	if original.Operations[0] != "execute" {
		t.Errorf("DeepCopy failed: original Operations mutated: %v", original.Operations)
	}
	if original.Arguments[0] != '{' {
		t.Errorf("DeepCopy failed: original Arguments mutated: %v", string(original.Arguments))
	}
	if original.Rules[0].Name != "rule1" {
		t.Errorf("DeepCopy failed: original Rules mutated: %v", original.Rules)
	}
}

func TestRequest_DeepCopy_NilSlices(t *testing.T) {
	original := Request{ToolName: "Read"}
	cp := original.DeepCopy()
	if cp.Paths != nil || cp.Hosts != nil || cp.Operations != nil || cp.Arguments != nil || cp.Rules != nil {
		t.Error("DeepCopy should preserve nil slices")
	}
}

func TestResult_EffectiveSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"critical", "critical"},
		{"high", "high"},
		{"warning", "warning"},
		{"info", "info"},
		{"banana", "high"},
		{"", "high"},
		{"CRITICAL", "high"}, // case-sensitive
	}
	for _, tt := range tests {
		r := &Result{Severity: tt.input}
		if got := r.EffectiveSeverity(); got != tt.want {
			t.Errorf("EffectiveSeverity(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestResult_EffectiveAction(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", "block"},
		{"block", "block"},
		{"log", "log"},
		{"alert", "alert"},
	}
	for _, tt := range tests {
		r := &Result{Action: tt.input}
		if got := r.EffectiveAction(); got != tt.want {
			t.Errorf("EffectiveAction(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// =============================================================================
// RuleSnapshot tests
// =============================================================================

func TestRuleSnapshot_JSONRoundTrip(t *testing.T) {
	snap := RuleSnapshot{
		Name:        "protect-env",
		Description: "Block .env file access",
		Source:      "builtin",
		Severity:    "critical",
		Priority:    10,
		Actions:     []string{"read", "write"},
		BlockPaths:  []string{"**/.env"},
		BlockExcept: []string{"**/.env.example"},
		Message:     "Cannot access .env files",
		Locked:      true,
		Enabled:     true,
		HitCount:    42,
	}

	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded RuleSnapshot
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if decoded.Name != snap.Name {
		t.Errorf("Name = %q, want %q", decoded.Name, snap.Name)
	}
	if decoded.Source != snap.Source {
		t.Errorf("Source = %q, want %q", decoded.Source, snap.Source)
	}
	if decoded.HitCount != snap.HitCount {
		t.Errorf("HitCount = %d, want %d", decoded.HitCount, snap.HitCount)
	}
	if len(decoded.BlockPaths) != 1 || decoded.BlockPaths[0] != "**/.env" {
		t.Errorf("BlockPaths = %v, want [**/.env]", decoded.BlockPaths)
	}
}

func TestRequest_RulesInJSON(t *testing.T) {
	// Verify that Request with rules serializes correctly over the wire protocol.
	req := Request{
		ToolName:  "Bash",
		Operation: "execute",
		Command:   "ls -la",
		Rules: []RuleSnapshot{
			{Name: "r1", Source: "builtin", Severity: "critical", Actions: []string{"read"}},
			{Name: "r2", Source: "user", Severity: "warning", Actions: []string{"write"}},
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded Request
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if len(decoded.Rules) != 2 {
		t.Fatalf("Rules count = %d, want 2", len(decoded.Rules))
	}
	if decoded.Rules[0].Name != "r1" || decoded.Rules[1].Name != "r2" {
		t.Errorf("Rules = %v", decoded.Rules)
	}
}

func TestRequest_EmptyRulesOmitted(t *testing.T) {
	// Rules with omitempty should not appear when nil.
	req := Request{ToolName: "Bash"}
	data, _ := json.Marshal(req)
	var m map[string]any
	json.Unmarshal(data, &m)
	if _, exists := m["rules"]; exists {
		t.Error("rules should be omitted when nil")
	}
}

// =============================================================================
// Wire protocol tests
// =============================================================================

func TestWireRequest_JSONFormat(t *testing.T) {
	params, _ := json.Marshal(InitParams{Name: "sandbox", Config: json.RawMessage(`{"allow":true}`)})
	req := WireRequest{Method: MethodInit, Params: params}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded WireRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded.Method != MethodInit {
		t.Errorf("Method = %q, want %q", decoded.Method, MethodInit)
	}
}

func TestWireResponse_AllowResult(t *testing.T) {
	// null result means allow.
	resp := WireResponse{Result: json.RawMessage("null")}
	data, _ := json.Marshal(resp)

	var decoded WireResponse
	json.Unmarshal(data, &decoded)
	if string(decoded.Result) != "null" {
		t.Errorf("Result = %s, want null", decoded.Result)
	}
}

func TestWireResponse_BlockResult(t *testing.T) {
	result, _ := json.Marshal(Result{
		RuleName: "sandbox:fs-deny",
		Severity: "high",
		Message:  "path outside sandbox",
	})
	resp := WireResponse{Result: result}
	data, _ := json.Marshal(resp)

	var decoded WireResponse
	json.Unmarshal(data, &decoded)

	var r Result
	json.Unmarshal(decoded.Result, &r)
	if r.RuleName != "sandbox:fs-deny" {
		t.Errorf("RuleName = %q, want %q", r.RuleName, "sandbox:fs-deny")
	}
}

func TestWireResponse_ErrorResult(t *testing.T) {
	resp := WireResponse{Error: "plugin crashed"}
	data, _ := json.Marshal(resp)

	var decoded WireResponse
	json.Unmarshal(data, &decoded)
	if decoded.Error != "plugin crashed" {
		t.Errorf("Error = %q, want %q", decoded.Error, "plugin crashed")
	}
}

func TestWireProtocol_EvaluateWithRules(t *testing.T) {
	// Full round-trip: Request with rules → wire → decode.
	req := Request{
		ToolName:  "Bash",
		Operation: "execute",
		Command:   "rm -rf /etc",
		Paths:     []string{"/etc"},
		Rules: []RuleSnapshot{
			{Name: "protect-etc", Source: "builtin", Severity: "critical", Actions: []string{"delete"}, BlockPaths: []string{"/etc/**"}},
		},
	}

	params, _ := json.Marshal(req)
	wireReq := WireRequest{Method: MethodEvaluate, Params: params}
	data, _ := json.Marshal(wireReq)

	// Simulate plugin receiving the request.
	var receivedWire WireRequest
	json.Unmarshal(data, &receivedWire)
	if receivedWire.Method != MethodEvaluate {
		t.Fatalf("Method = %q, want %q", receivedWire.Method, MethodEvaluate)
	}

	var receivedReq Request
	json.Unmarshal(receivedWire.Params, &receivedReq)
	if len(receivedReq.Rules) != 1 {
		t.Fatalf("Rules count = %d, want 1", len(receivedReq.Rules))
	}
	if receivedReq.Rules[0].Name != "protect-etc" {
		t.Errorf("Rule name = %q, want %q", receivedReq.Rules[0].Name, "protect-etc")
	}
	if receivedReq.Rules[0].BlockPaths[0] != "/etc/**" {
		t.Errorf("BlockPaths = %v", receivedReq.Rules[0].BlockPaths)
	}
}

// =============================================================================
// Pool tests
// =============================================================================

func TestPool_BasicExecution(t *testing.T) {
	pool := NewPool(4, time.Second)
	ctx := context.Background()

	result, err := pool.Run(ctx, func(context.Context) *Result {
		return &Result{RuleName: "test", Severity: "high", Message: "blocked"}
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil || result.RuleName != "test" {
		t.Errorf("unexpected result: %v", result)
	}
}

func TestPool_PanicRecovery(t *testing.T) {
	pool := NewPool(4, time.Second)
	ctx := context.Background()

	result, err := pool.Run(ctx, func(context.Context) *Result {
		panic("boom")
	})
	if err == nil {
		t.Fatal("expected error from panic")
	}
	if result != nil {
		t.Errorf("expected nil result from panic, got %v", result)
	}
	if !strings.Contains(err.Error(), "panic: boom") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPool_Timeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := NewPool(4, 5*time.Second) // fake clock — runs instantly
		result, err := pool.Run(t.Context(), func(ctx context.Context) *Result {
			<-ctx.Done()
			return nil
		})
		if !errors.Is(err, ErrTimeout) {
			t.Fatalf("expected ErrTimeout, got %v", err)
		}
		if result != nil {
			t.Errorf("expected nil result on timeout, got %v", result)
		}
	})
}

func TestPool_SlotExhaustion(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := NewPool(1, time.Minute)

		blocker := make(chan struct{})
		go pool.Run(t.Context(), func(context.Context) *Result { //nolint:unparam // must match Pool.Run signature
			<-blocker
			return nil
		})
		synctest.Wait() // deterministic: goroutine has acquired the slot

		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		_, err := pool.Run(ctx, func(context.Context) *Result { return nil })
		if !errors.Is(err, ErrPoolExhausted) {
			t.Fatalf("expected ErrPoolExhausted, got %v", err)
		}

		close(blocker)
	})
}

func TestPool_ConcurrentExecution(t *testing.T) {
	pool := NewPool(4, time.Second)
	ctx := context.Background()
	var running atomic.Int64
	var maxRunning atomic.Int64

	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			pool.Run(ctx, func(context.Context) *Result {
				cur := running.Add(1)
				defer running.Add(-1)
				for {
					old := maxRunning.Load()
					if cur <= old || maxRunning.CompareAndSwap(old, cur) {
						break
					}
				}
				time.Sleep(10 * time.Millisecond)
				return nil
			})
		})
	}
	wg.Wait()

	if peak := maxRunning.Load(); peak > 4 {
		t.Errorf("pool allowed %d concurrent executions, max should be 4", peak)
	}
}

func TestPool_CooperativeTimeout_NoGoroutineLeak(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := NewPool(4, 5*time.Second) // fake clock — runs instantly
		var completed atomic.Bool

		_, err := pool.Run(t.Context(), func(ctx context.Context) *Result {
			<-ctx.Done()
			completed.Store(true)
			return nil
		})
		if !errors.Is(err, ErrTimeout) {
			t.Fatalf("expected ErrTimeout, got %v", err)
		}
		synctest.Wait() // deterministic: goroutine has finished
		if !completed.Load() {
			t.Error("goroutine should have completed after ctx cancellation")
		}
	})
}

// =============================================================================
// Registry tests
// =============================================================================

func TestRegistry_Register(t *testing.T) {
	reg := NewRegistry(NewPool(4, time.Second))
	defer reg.Close()

	err := reg.Register(&allowPlugin{name: "test"}, nil)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if names := reg.List(); len(names) != 1 || names[0] != "test" {
		t.Errorf("List = %v, want [test]", names)
	}
}

func TestRegistry_RegisterDuplicateName(t *testing.T) {
	reg := NewRegistry(NewPool(4, time.Second))
	defer reg.Close()

	reg.Register(&allowPlugin{name: "dup"}, nil)
	err := reg.Register(&allowPlugin{name: "dup"}, nil)
	if err == nil {
		t.Fatal("expected error for duplicate name")
	}
}

func TestRegistry_RegisterEmptyName(t *testing.T) {
	reg := NewRegistry(NewPool(4, time.Second))
	defer reg.Close()

	err := reg.Register(&allowPlugin{name: ""}, nil)
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestRegistry_RegisterInitFail(t *testing.T) {
	reg := NewRegistry(NewPool(4, time.Second))
	defer reg.Close()

	err := reg.Register(&initFailPlugin{name: "bad"}, nil)
	if err == nil {
		t.Fatal("expected error from Init failure")
	}
	if reg.Len() != 0 {
		t.Error("failed plugin should not be registered")
	}
}

func TestRegistry_EvaluateAllow(t *testing.T) {
	reg := NewRegistry(NewPool(4, time.Second))
	defer reg.Close()

	reg.Register(&allowPlugin{name: "p1"}, nil)
	reg.Register(&allowPlugin{name: "p2"}, nil)
	result := reg.Evaluate(context.Background(), Request{ToolName: "Bash"})
	if result != nil {
		t.Errorf("expected nil (allow), got %v", result)
	}
}

func TestRegistry_EvaluateBlock(t *testing.T) {
	reg := NewRegistry(NewPool(4, time.Second))
	defer reg.Close()

	reg.Register(&allowPlugin{name: "p1"}, nil)
	reg.Register(&blockPlugin{
		name:   "blocker",
		result: Result{RuleName: "test:block", Severity: "high", Message: "denied"},
	}, nil)
	result := reg.Evaluate(context.Background(), Request{ToolName: "Bash"})
	if result == nil {
		t.Fatal("expected block result")
	}
	if result.Plugin != "blocker" {
		t.Errorf("Plugin = %q, want %q", result.Plugin, "blocker")
	}
}

func TestRegistry_FirstBlockWins(t *testing.T) {
	reg := NewRegistry(NewPool(4, time.Second))
	defer reg.Close()

	reg.Register(&blockPlugin{name: "first",
		result: Result{RuleName: "first:block", Severity: "high", Message: "first"},
	}, nil)
	reg.Register(&blockPlugin{name: "second",
		result: Result{RuleName: "second:block", Severity: "high", Message: "second"},
	}, nil)

	result := reg.Evaluate(context.Background(), Request{ToolName: "Bash"})
	if result == nil || result.Plugin != "first" {
		t.Errorf("expected first plugin to win, got %v", result)
	}
}

// =============================================================================
// Rule-aware plugin tests
// =============================================================================

func TestRegistry_PluginReceivesRules(t *testing.T) {
	reg := NewRegistry(NewPool(4, time.Second))
	defer reg.Close()

	var store atomic.Value
	reg.Register(&inspectPlugin{name: "inspector", store: &store}, nil)
	rules := []RuleSnapshot{
		{Name: "protect-env", Source: "builtin", Severity: "critical", Actions: []string{"read"}, BlockPaths: []string{"**/.env"}, Locked: true, Enabled: true},
		{Name: "protect-ssh", Source: "builtin", Severity: "critical", Actions: []string{"read"}, BlockPaths: []string{"$HOME/.ssh/id_*"}, Locked: true, Enabled: true},
		{Name: "user-custom", Source: "user", Severity: "warning", Actions: []string{"write"}, BlockPaths: []string{"/tmp/secret"}, Enabled: true},
	}

	reg.Evaluate(context.Background(), Request{
		ToolName:  "Read",
		Operation: "read",
		Paths:     []string{"/home/user/.env"},
		Rules:     rules,
	})

	seen := store.Load().(Request)
	if len(seen.Rules) != 3 {
		t.Fatalf("plugin received %d rules, want 3", len(seen.Rules))
	}
	if seen.Rules[0].Name != "protect-env" {
		t.Errorf("first rule = %q, want %q", seen.Rules[0].Name, "protect-env")
	}
	if !seen.Rules[0].Locked {
		t.Error("protect-env should be locked")
	}
	if seen.Rules[2].Source != "user" {
		t.Errorf("third rule source = %q, want %q", seen.Rules[2].Source, "user")
	}
}

func TestRegistry_RuleAwarePlugin_BlocksWhenRuleMissing(t *testing.T) {
	reg := NewRegistry(NewPool(4, time.Second))
	defer reg.Close()

	reg.Register(&ruleAwarePlugin{name: "policy", requiredRule: "protect-env"}, nil)
	// Without rules — should block.
	result := reg.Evaluate(context.Background(), Request{ToolName: "Read", Rules: nil})
	if result == nil {
		t.Fatal("expected block when required rule is missing")
	}
	if result.RuleName != "policy:missing-rule" {
		t.Errorf("RuleName = %q, want %q", result.RuleName, "policy:missing-rule")
	}
}

func TestRegistry_RuleAwarePlugin_AllowsWhenRulePresent(t *testing.T) {
	reg := NewRegistry(NewPool(4, time.Second))
	defer reg.Close()

	reg.Register(&ruleAwarePlugin{name: "policy", requiredRule: "protect-env"}, nil)
	result := reg.Evaluate(context.Background(), Request{
		ToolName: "Read",
		Rules:    []RuleSnapshot{{Name: "protect-env"}},
	})
	if result != nil {
		t.Errorf("expected allow when required rule exists, got %v", result)
	}
}

func TestRegistry_RuleSnapshotProperties(t *testing.T) {
	reg := NewRegistry(NewPool(4, time.Second))
	defer reg.Close()

	var store atomic.Value
	reg.Register(&inspectPlugin{name: "inspector", store: &store}, nil)
	reg.Evaluate(context.Background(), Request{
		ToolName: "Bash",
		Rules: []RuleSnapshot{
			{
				Name:        "protect-etc",
				Description: "Block /etc access",
				Source:      "builtin",
				Severity:    "critical",
				Priority:    10,
				Actions:     []string{"read", "write", "delete"},
				BlockPaths:  []string{"/etc/**"},
				BlockExcept: []string{"/etc/hostname"},
				BlockHosts:  nil,
				Message:     "Cannot modify system files",
				Locked:      true,
				Enabled:     true,
				HitCount:    99,
			},
		},
	})

	seen := store.Load().(Request)
	r := seen.Rules[0]
	if r.Description != "Block /etc access" {
		t.Errorf("Description = %q", r.Description)
	}
	if r.Priority != 10 {
		t.Errorf("Priority = %d", r.Priority)
	}
	if len(r.Actions) != 3 {
		t.Errorf("Actions = %v", r.Actions)
	}
	if len(r.BlockExcept) != 1 || r.BlockExcept[0] != "/etc/hostname" {
		t.Errorf("BlockExcept = %v", r.BlockExcept)
	}
	if r.HitCount != 99 {
		t.Errorf("HitCount = %d", r.HitCount)
	}
}

// =============================================================================
// Crash isolation tests
// =============================================================================

func TestRegistry_PanicRecovery(t *testing.T) {
	reg := NewRegistry(NewPool(4, time.Second))
	defer reg.Close()

	counter := &countPlugin{name: "counter"}
	reg.Register(&panicPlugin{name: "crasher"}, nil)
	reg.Register(counter, nil)
	result := reg.Evaluate(context.Background(), Request{ToolName: "Bash"})
	if result != nil {
		t.Errorf("expected nil (fail-open after panic), got %v", result)
	}
	if counter.calls.Load() != 1 {
		t.Errorf("counter plugin should have been called once, got %d", counter.calls.Load())
	}
}

func TestRegistry_TimeoutRecovery(t *testing.T) {
	pool := NewPool(4, 50*time.Millisecond)
	reg := NewRegistry(pool)
	defer reg.Close()

	counter := &countPlugin{name: "counter"}
	reg.Register(&hangPlugin{name: "hanger"}, nil)
	reg.Register(counter, nil)
	result := reg.Evaluate(context.Background(), Request{ToolName: "Bash"})
	if result != nil {
		t.Errorf("expected nil (fail-open after timeout), got %v", result)
	}
	if counter.calls.Load() != 1 {
		t.Error("counter plugin should have been called after timeout")
	}
}

// =============================================================================
// Circuit breaker tests
// =============================================================================

func TestRegistry_CircuitBreaker_DisableAfterFailures(t *testing.T) {
	pool := NewPool(4, 50*time.Millisecond)
	reg := NewRegistry(pool)
	defer reg.Close()

	counter := &countPlugin{name: "counter"}
	reg.Register(&panicPlugin{name: "crasher"}, nil)
	reg.Register(counter, nil)
	ctx := context.Background()
	for range MaxConsecutiveFailures {
		reg.Evaluate(ctx, Request{ToolName: "Bash"})
	}

	stats := reg.Stats()
	if !stats[0].Disabled {
		t.Error("plugin should be disabled after max failures")
	}
	if stats[0].TotalPanics != int64(MaxConsecutiveFailures) {
		t.Errorf("total panics = %d, want %d", stats[0].TotalPanics, MaxConsecutiveFailures)
	}

	counterBefore := counter.calls.Load()
	reg.Evaluate(ctx, Request{ToolName: "Bash"})
	if counter.calls.Load() != counterBefore+1 {
		t.Error("counter should still be called when crasher is disabled")
	}
}

func TestRegistry_CircuitBreaker_SuccessResetsCounter(t *testing.T) {
	pool := NewPool(4, 50*time.Millisecond)
	reg := NewRegistry(pool)
	defer reg.Close()

	failCount := &atomic.Int64{}
	plugin := &conditionalPlugin{
		name:      "flaky",
		failCount: failCount,
		threshold: int64(MaxConsecutiveFailures - 1),
	}
	reg.Register(plugin, nil)
	ctx := context.Background()
	for range MaxConsecutiveFailures - 1 {
		reg.Evaluate(ctx, Request{ToolName: "Bash"})
	}

	stats := reg.Stats()
	if stats[0].Disabled {
		t.Error("plugin should NOT be disabled yet")
	}

	reg.Evaluate(ctx, Request{ToolName: "Bash"})

	stats = reg.Stats()
	if stats[0].Failures != 0 {
		t.Errorf("failures should be reset to 0 after success, got %d", stats[0].Failures)
	}
}

func TestRegistry_CircuitBreaker_ExponentialBackoff(t *testing.T) {
	if d := cooldownFor(1); d != CircuitResetInterval {
		t.Errorf("cycle 1 cooldown = %v, want %v", d, CircuitResetInterval)
	}
	if d := cooldownFor(2); d != CircuitResetInterval*2 {
		t.Errorf("cycle 2 cooldown = %v, want %v", d, CircuitResetInterval*2)
	}
	if d := cooldownFor(3); d != CircuitResetInterval*4 {
		t.Errorf("cycle 3 cooldown = %v, want %v", d, CircuitResetInterval*4)
	}
	if d := cooldownFor(100); d != time.Hour {
		t.Errorf("cycle 100 cooldown = %v, want %v", d, time.Hour)
	}
}

func TestRegistry_CircuitBreaker_PermanentDisable(t *testing.T) {
	pool := NewPool(4, 50*time.Millisecond)
	reg := NewRegistry(pool)
	defer reg.Close()

	reg.Register(&panicPlugin{name: "crasher"}, nil)
	ctx := context.Background()

	reg.mu.RLock()
	s := reg.states[0]
	reg.mu.RUnlock()

	s.disableCycles.Store(int64(MaxDisableCycles))
	s.disabled.Store(true)
	s.disabledAt.Store(0)

	reg.Evaluate(ctx, Request{ToolName: "Bash"})

	stats := reg.Stats()
	if !stats[0].Permanent {
		t.Error("plugin should be permanently disabled")
	}
	if !stats[0].Disabled {
		t.Error("plugin should still be disabled")
	}
}

func TestRegistry_CircuitBreaker_ConcurrentReEnable(t *testing.T) {
	pool := NewPool(8, 50*time.Millisecond)
	reg := NewRegistry(pool)
	defer reg.Close()

	counter := &countPlugin{name: "counter"}
	reg.Register(&panicPlugin{name: "crasher"}, nil)
	reg.Register(counter, nil)
	ctx := context.Background()
	for range MaxConsecutiveFailures {
		reg.Evaluate(ctx, Request{ToolName: "Bash"})
	}

	reg.mu.RLock()
	s := reg.states[0]
	reg.mu.RUnlock()
	s.disabledAt.Store(time.Now().Add(-CircuitResetInterval * 2).UnixNano())

	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			reg.Evaluate(ctx, Request{ToolName: "Bash"})
		})
	}
	wg.Wait()

	stats := reg.Stats()
	if !stats[0].Disabled {
		t.Log("plugin re-enabled (race benign in this test)")
	}
}

// =============================================================================
// Bug 6.2: Plugin Name() spoofing
// =============================================================================

func TestRegistry_NameCachedAtRegistration(t *testing.T) {
	reg := NewRegistry(NewPool(4, time.Second))
	defer reg.Close()

	dp := &dynamicNamePlugin{}
	err := reg.Register(dp, nil)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	result := reg.Evaluate(context.Background(), Request{ToolName: "Bash"})
	if result == nil {
		t.Fatal("expected block result")
	}
	if result.Plugin != "dynamic-1" {
		t.Errorf("Plugin = %q, want %q (cached at registration)", result.Plugin, "dynamic-1")
	}
}

// =============================================================================
// Bug 6.4: Request slice mutation across plugins
// =============================================================================

func TestRegistry_RequestIsolationBetweenPlugins(t *testing.T) {
	reg := NewRegistry(NewPool(4, time.Second))
	defer reg.Close()

	var secondSaw atomic.Value
	reg.Register(&mutatingPlugin{name: "mutator"}, nil)
	reg.Register(&inspectPlugin{name: "inspector", store: &secondSaw}, nil)
	req := Request{
		ToolName: "Bash",
		Paths:    []string{"/home/user/safe"},
		Hosts:    []string{"good.com"},
		Rules:    []RuleSnapshot{{Name: "rule1"}},
	}
	reg.Evaluate(context.Background(), req)

	seen := secondSaw.Load().(Request)
	if len(seen.Paths) > 0 && seen.Paths[0] != "/home/user/safe" {
		t.Errorf("second plugin saw mutated path: %v", seen.Paths)
	}
	if len(seen.Hosts) > 0 && seen.Hosts[0] != "good.com" {
		t.Errorf("second plugin saw mutated host: %v", seen.Hosts)
	}
	if len(seen.Rules) > 0 && seen.Rules[0].Name != "rule1" {
		t.Errorf("second plugin saw mutated rule: %v", seen.Rules)
	}
}

// =============================================================================
// Bug 5.2: Invalid severity validation
// =============================================================================

func TestRegistry_InvalidSeverityDefaultsToHigh(t *testing.T) {
	reg := NewRegistry(NewPool(4, time.Second))
	defer reg.Close()

	reg.Register(&blockPlugin{name: "bad-severity",
		result: Result{RuleName: "test", Severity: "banana", Message: "test"},
	}, nil)

	result := reg.Evaluate(context.Background(), Request{ToolName: "Bash"})
	if result == nil {
		t.Fatal("expected block result")
	}
	if result.Severity != "high" {
		t.Errorf("Severity = %q, want %q (default for invalid)", result.Severity, "high")
	}
}

// =============================================================================
// Bug 7.5: Close/Evaluate race
// =============================================================================

func TestRegistry_CloseRejectsNewEvaluate(t *testing.T) {
	reg := NewRegistry(NewPool(4, time.Second))

	counter := &countPlugin{name: "counter"}
	reg.Register(counter, nil)
	reg.Close()

	result := reg.Evaluate(context.Background(), Request{ToolName: "Bash"})
	if result != nil {
		t.Errorf("expected nil after Close, got %v", result)
	}

	err := reg.Register(&allowPlugin{name: "late"}, nil)
	if err == nil {
		t.Error("expected error registering after Close")
	}
}

// =============================================================================
// Concurrent stress tests
// =============================================================================

func TestRegistry_ConcurrentEvaluate(t *testing.T) {
	reg := NewRegistry(NewPool(4, time.Second))
	defer reg.Close()

	reg.Register(&allowPlugin{name: "p1"}, nil)
	reg.Register(&blockPlugin{
		name:   "p2",
		result: Result{RuleName: "test", Severity: "high", Message: "block"},
	}, nil)

	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			result := reg.Evaluate(context.Background(), Request{ToolName: "Bash"})
			if result == nil || result.Plugin != "p2" {
				t.Errorf("unexpected result: %v", result)
			}
		})
	}
	wg.Wait()
}

func TestRegistry_ConcurrentEvaluateWithPanics(t *testing.T) {
	pool := NewPool(8, time.Second)
	reg := NewRegistry(pool)
	defer reg.Close()

	reg.Register(&panicPlugin{name: "crasher"}, nil)
	reg.Register(&allowPlugin{name: "healthy"}, nil)
	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			reg.Evaluate(context.Background(), Request{ToolName: "Bash"})
		})
	}
	wg.Wait()

	stats := reg.Stats()
	if stats[0].TotalPanics == 0 {
		t.Error("expected panics to be recorded")
	}
}

// =============================================================================
// Stats / diagnostics tests
// =============================================================================

func TestRegistry_Stats(t *testing.T) {
	pool := NewPool(4, 50*time.Millisecond)
	reg := NewRegistry(pool)
	defer reg.Close()

	reg.Register(&panicPlugin{name: "crasher"}, nil)
	reg.Register(&allowPlugin{name: "healthy"}, nil)
	ctx := context.Background()
	for range 5 {
		reg.Evaluate(ctx, Request{ToolName: "Bash"})
	}

	stats := reg.Stats()
	if len(stats) != 2 {
		t.Fatalf("expected 2 stats entries, got %d", len(stats))
	}

	crasher := stats[0]
	if crasher.Name != "crasher" {
		t.Errorf("name = %q, want %q", crasher.Name, "crasher")
	}
	if crasher.TotalPanics < int64(MaxConsecutiveFailures) {
		t.Errorf("total panics = %d, want >= %d", crasher.TotalPanics, MaxConsecutiveFailures)
	}
	if !crasher.Disabled {
		t.Error("crasher should be disabled")
	}

	healthy := stats[1]
	if healthy.Disabled {
		t.Error("healthy plugin should not be disabled")
	}
}

// =============================================================================
// ProcessPlugin unit tests (without spawning a real process)
// =============================================================================

func TestProcessPlugin_Name(t *testing.T) {
	p := NewProcessPlugin("sandbox", "/usr/bin/sandbox-plugin")
	if p.Name() != "sandbox" {
		t.Errorf("Name() = %q, want %q", p.Name(), "sandbox")
	}
}

func TestProcessPlugin_InitFailsWithBadPath(t *testing.T) {
	p := NewProcessPlugin("bad", "/nonexistent/plugin")
	err := p.Init(nil)
	if err == nil {
		t.Fatal("expected error for nonexistent plugin binary")
	}
}

func TestProcessPlugin_EvaluateWhenNotStarted(t *testing.T) {
	p := &ProcessPlugin{name: "dead"}
	// Should fail-open when process is not running.
	result := p.Evaluate(context.Background(), Request{ToolName: "Bash"})
	if result != nil {
		t.Errorf("expected nil (fail-open) when process not running, got %v", result)
	}
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkRegistry_Evaluate_Allow(b *testing.B) {
	reg := NewRegistry(NewPool(8, time.Second))
	defer reg.Close()

	reg.Register(&allowPlugin{name: "p1"}, nil)
	reg.Register(&allowPlugin{name: "p2"}, nil)
	req := Request{
		ToolName:  "Bash",
		Operation: "execute",
		Paths:     []string{"/home/user/project/main.go"},
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		reg.Evaluate(ctx, req)
	}
}

func BenchmarkRegistry_Evaluate_AllowWithRules(b *testing.B) {
	reg := NewRegistry(NewPool(8, time.Second))
	defer reg.Close()

	reg.Register(&allowPlugin{name: "p1"}, nil)
	rules := make([]RuleSnapshot, 50) // typical rule count
	for i := range rules {
		rules[i] = RuleSnapshot{
			Name:     fmt.Sprintf("rule-%d", i),
			Source:   "builtin",
			Severity: "critical",
			Actions:  []string{"read", "write"},
		}
	}

	req := Request{
		ToolName:  "Bash",
		Operation: "execute",
		Paths:     []string{"/home/user/project/main.go"},
		Rules:     rules,
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		reg.Evaluate(ctx, req)
	}
}

func BenchmarkRegistry_Evaluate_Block(b *testing.B) {
	reg := NewRegistry(NewPool(8, time.Second))
	defer reg.Close()

	reg.Register(&blockPlugin{name: "blocker",
		result: Result{RuleName: "test", Severity: "high", Message: "denied"},
	}, nil)

	req := Request{
		ToolName:  "Bash",
		Operation: "execute",
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		reg.Evaluate(ctx, req)
	}
}

func BenchmarkPool_Run(b *testing.B) {
	pool := NewPool(8, time.Second)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		pool.Run(ctx, func(context.Context) *Result { return nil })
	}
}

func BenchmarkRegistry_Evaluate_Parallel(b *testing.B) {
	reg := NewRegistry(NewPool(8, time.Second))
	defer reg.Close()

	reg.Register(&allowPlugin{name: "p1"}, nil)
	req := Request{
		ToolName:  "Bash",
		Operation: "execute",
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			reg.Evaluate(ctx, req)
		}
	})
}
