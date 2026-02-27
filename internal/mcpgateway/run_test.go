package mcpgateway

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/BakeLens/crust/internal/jsonrpc"
	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/rules"
)

var testLog = logger.New("mcp-test")

func newTestEngine(t *testing.T) *rules.Engine {
	t.Helper()
	engine, err := rules.NewEngine(rules.EngineConfig{
		UserRulesDir:   t.TempDir(),
		DisableBuiltin: false,
	})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	return engine
}

// runPipe runs PipeInspect with MCPMethodToToolCall and returns what was
// forwarded and what error responses were generated.
func runPipe(t *testing.T, input string) (fwd, errOut string) {
	t.Helper()
	engine := newTestEngine(t)
	var fwdBuf, errBuf bytes.Buffer
	fwdWriter := jsonrpc.NewLockedWriter(&fwdBuf)
	errWriter := jsonrpc.NewLockedWriter(&errBuf)
	jsonrpc.PipeInspect(testLog, engine, strings.NewReader(input),
		fwdWriter, errWriter, MCPMethodToToolCall, "MCP", "Client->Server")
	return fwdBuf.String(), errBuf.String()
}

// --- Edge-case blocking (malformed inputs, resources/read) ---
// Security blocking of .env, .ssh, etc. is covered by E2E tests (e2e_test.go).

func TestPipeClientToServer_BlocksEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		msg  string
	}{
		{"resource_env_read", `{"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"file:///app/.env"}}`},
		{"malformed_tools_call", `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":"not-an-object"}`},
		{"null_params", `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":null}`},
		{"empty_tool_name", `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"","arguments":{}}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fwd, errOut := runPipe(t, tt.msg+"\n")
			if fwd != "" {
				t.Errorf("server should not receive blocked request, got: %s", fwd)
			}
			if errOut == "" {
				t.Error("client should receive an error response")
			}
		})
	}
}

// --- Passthrough edge cases ---
// Passthrough of initialize, tools/list, and allowed tool calls is covered by E2E tests.

func TestPipeClientToServer_PassesEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		msg  string
	}{
		{"notification", `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`}, //nolint:misspell // MCP protocol uses "cancelled"
		{"response", `{"jsonrpc":"2.0","id":5,"result":{"content":"file data"}}`},
		{"invalid_json", `not valid json at all`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fwd, errOut := runPipe(t, tt.msg+"\n")
			if fwd != tt.msg+"\n" {
				t.Errorf("message should pass through unchanged\ngot:  %q\nwant: %q", fwd, tt.msg+"\n")
			}
			if errOut != "" {
				t.Errorf("client should not receive errors, got: %s", errOut)
			}
		})
	}
}

// --- resources/read error response shape ---

func TestPipeClientToServer_ResourceReadErrorShape(t *testing.T) {
	fwd, errOut := runPipe(t, `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///app/.env"}}`+"\n")
	if fwd != "" {
		t.Errorf("server should not receive blocked request, got: %s", fwd)
	}
	var resp jsonrpc.ErrorResponse
	if err := json.Unmarshal(bytes.TrimSpace([]byte(errOut)), &resp); err != nil {
		t.Fatalf("expected JSON-RPC error, got: %s", errOut)
	}
	if resp.Error.Code != jsonrpc.BlockedError {
		t.Errorf("error code = %d, want %d", resp.Error.Code, jsonrpc.BlockedError)
	}
	if !strings.Contains(resp.Error.Message, "[Crust]") {
		t.Errorf("error message missing [Crust]: %s", resp.Error.Message)
	}
}
