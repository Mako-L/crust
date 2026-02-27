package mcpgateway

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BakeLens/crust/internal/jsonrpc"
)

// skipE2E skips if -short or npx not available.
func skipE2E(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("E2E: skipped in -short mode")
	}
	if _, err := exec.LookPath("npx"); err != nil {
		t.Skip("E2E: npx not found in PATH")
	}
}

// setupTestDir creates a temp directory with test files for the filesystem server.
// It resolves symlinks so paths match on macOS (/var → /private/var).
func setupTestDir(t *testing.T) string {
	t.Helper()
	raw := t.TempDir()
	dir, err := filepath.EvalSymlinks(raw)
	if err != nil {
		t.Fatalf("failed to resolve symlinks for %s: %v", raw, err)
	}

	// Safe files
	os.WriteFile(filepath.Join(dir, "safe.txt"), []byte("hello world"), 0o644)
	os.MkdirAll(filepath.Join(dir, "subdir"), 0o755)
	os.WriteFile(filepath.Join(dir, "subdir", "code.go"), []byte("package main"), 0o644)

	// Sensitive files (should be blocked by Crust)
	os.WriteFile(filepath.Join(dir, ".env"), []byte("SECRET_KEY=sk-1234"), 0o644)
	os.MkdirAll(filepath.Join(dir, ".ssh"), 0o700)
	os.WriteFile(filepath.Join(dir, ".ssh", "id_rsa"), []byte("fake-private-key"), 0o600)

	return dir
}

// e2eResponse represents a parsed JSON-RPC response from the proxy output.
type e2eResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// runMCPE2E runs the MCP proxy against the real filesystem server and returns
// all JSON-RPC responses received by the client.
func runMCPE2E(t *testing.T, dir string, messages []string) []e2eResponse {
	t.Helper()
	engine := newTestEngine(t)
	input := strings.Join(messages, "\n") + "\n"
	stdinR := io.NopCloser(strings.NewReader(input))
	var stdout strings.Builder

	done := make(chan int, 1)
	go func() {
		done <- jsonrpc.RunProxy(engine,
			[]string{"npx", "-y", "@modelcontextprotocol/server-filesystem", dir},
			stdinR, &stdout, jsonrpc.ProxyConfig{
				Log:          testLog,
				ProcessLabel: "MCP server",
				Inbound:      jsonrpc.PipeConfig{Label: "Client->Server", Protocol: "MCP", Convert: MCPMethodToToolCall},
				Outbound:     jsonrpc.PipeConfig{Label: "Server->Client"},
			})
	}()

	select {
	case <-done:
		return parseE2EResponses(t, stdout.String())
	case <-time.After(30 * time.Second):
		t.Fatal("E2E test timed out (30s)")
		return nil
	}
}

// parseE2EResponses parses JSONL output into e2eResponse structs.
func parseE2EResponses(t *testing.T, output string) []e2eResponse {
	t.Helper()
	var responses []e2eResponse
	for line := range strings.SplitSeq(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var resp e2eResponse
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			t.Logf("skipping non-JSON line: %s", line)
			continue
		}
		responses = append(responses, resp)
	}
	return responses
}

// findByID finds a response with the given integer ID.
func findByID(responses []e2eResponse, id int) *e2eResponse {
	target := fmt.Sprintf("%d", id)
	for i := range responses {
		if string(responses[i].ID) == target {
			return &responses[i]
		}
	}
	return nil
}

// initMessages returns the standard MCP handshake messages (initialize + initialized notification).
func initMessages() []string {
	return []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"crust-e2e","version":"1.0.0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`,
	}
}

// --- E2E Tests ---

func TestE2E_Initialize(t *testing.T) {
	skipE2E(t)
	dir := setupTestDir(t)

	responses := runMCPE2E(t, dir, initMessages()[:1]) // just initialize, no notification

	resp := findByID(responses, 1)
	if resp == nil {
		t.Fatal("no response for initialize (id=1)")
	}
	if resp.Error != nil {
		t.Fatalf("initialize returned error: %s", resp.Error.Message)
	}

	// Verify response has protocolVersion
	var result map[string]any
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("failed to parse init result: %v", err)
	}
	if _, ok := result["protocolVersion"]; !ok {
		t.Error("initialize response missing protocolVersion")
	}
	if _, ok := result["capabilities"]; !ok {
		t.Error("initialize response missing capabilities")
	}
	if _, ok := result["serverInfo"]; !ok {
		t.Error("initialize response missing serverInfo")
	}
}

func TestE2E_ToolsList(t *testing.T) {
	skipE2E(t)
	dir := setupTestDir(t)

	messages := append(initMessages(),
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
	)
	responses := runMCPE2E(t, dir, messages)

	resp := findByID(responses, 2)
	if resp == nil {
		t.Fatal("no response for tools/list (id=2)")
	}
	if resp.Error != nil {
		t.Fatalf("tools/list returned error: %s", resp.Error.Message)
	}

	var result map[string]any
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("failed to parse tools/list result: %v", err)
	}
	tools, ok := result["tools"].([]any)
	if !ok || len(tools) == 0 {
		t.Fatal("tools/list returned no tools")
	}

	// Verify known tools exist
	toolNames := make(map[string]bool)
	for _, tool := range tools {
		if m, ok := tool.(map[string]any); ok {
			if name, ok := m["name"].(string); ok {
				toolNames[name] = true
			}
		}
	}
	for _, want := range []string{"read_text_file", "write_file"} {
		if !toolNames[want] {
			t.Errorf("tools/list missing tool %q, got: %v", want, toolNames)
		}
	}
}

func TestE2E_ReadAllowed(t *testing.T) {
	skipE2E(t)
	dir := setupTestDir(t)

	messages := append(initMessages(),
		fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"%s/safe.txt"}}}`, dir),
	)
	responses := runMCPE2E(t, dir, messages)

	resp := findByID(responses, 3)
	if resp == nil {
		t.Fatal("no response for read_text_file safe.txt (id=3)")
	}
	if resp.Error != nil {
		t.Fatalf("read_text_file returned error: code=%d msg=%s", resp.Error.Code, resp.Error.Message)
	}

	// Verify the response contains the actual file content
	if !strings.Contains(string(resp.Result), "hello world") {
		t.Errorf("expected file content 'hello world' in response, got: %s", string(resp.Result))
	}
}

func TestE2E_ReadBlocked_Env(t *testing.T) {
	skipE2E(t)
	dir := setupTestDir(t)

	messages := append(initMessages(),
		fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"%s/.env"}}}`, dir),
	)
	responses := runMCPE2E(t, dir, messages)

	resp := findByID(responses, 3)
	if resp == nil {
		t.Fatal("no response for blocked .env read (id=3)")
	}
	if resp.Error == nil {
		t.Fatalf("expected Crust block error for .env read, got success: %s", string(resp.Result))
	}
	if resp.Error.Code != jsonrpc.BlockedError {
		t.Errorf("error code = %d, want %d", resp.Error.Code, jsonrpc.BlockedError)
	}
	if !strings.Contains(resp.Error.Message, "[Crust]") {
		t.Errorf("error message missing [Crust] prefix: %s", resp.Error.Message)
	}
}

func TestE2E_ReadBlocked_SSHKey(t *testing.T) {
	skipE2E(t)
	dir := setupTestDir(t)

	messages := append(initMessages(),
		fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"%s/.ssh/id_rsa"}}}`, dir),
	)
	responses := runMCPE2E(t, dir, messages)

	resp := findByID(responses, 3)
	if resp == nil {
		t.Fatal("no response for blocked SSH key read (id=3)")
	}
	if resp.Error == nil {
		t.Fatalf("expected Crust block error for SSH key read, got success: %s", string(resp.Result))
	}
	if resp.Error.Code != jsonrpc.BlockedError {
		t.Errorf("error code = %d, want %d", resp.Error.Code, jsonrpc.BlockedError)
	}
}

func TestE2E_WriteAllowed(t *testing.T) {
	skipE2E(t)
	dir := setupTestDir(t)
	outFile := filepath.Join(dir, "output.txt")

	messages := append(initMessages(),
		fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"%s","content":"written by e2e test"}}}`, outFile),
	)
	responses := runMCPE2E(t, dir, messages)

	resp := findByID(responses, 3)
	if resp == nil {
		t.Fatal("no response for write_file (id=3)")
	}
	if resp.Error != nil {
		t.Fatalf("write_file returned error: code=%d msg=%s", resp.Error.Code, resp.Error.Message)
	}

	// Verify the file was actually written
	content, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("failed to read written file: %v", err)
	}
	if string(content) != "written by e2e test" {
		t.Errorf("file content = %q, want %q", string(content), "written by e2e test")
	}
}

func TestE2E_WriteBlocked_Env(t *testing.T) {
	skipE2E(t)
	dir := setupTestDir(t)
	envContent, _ := os.ReadFile(filepath.Join(dir, ".env"))

	messages := append(initMessages(),
		fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"%s/.env","content":"STOLEN=true"}}}`, dir),
	)
	responses := runMCPE2E(t, dir, messages)

	resp := findByID(responses, 3)
	if resp == nil {
		t.Fatal("no response for blocked .env write (id=3)")
	}
	if resp.Error == nil {
		t.Fatalf("expected Crust block error for .env write, got success: %s", string(resp.Result))
	}
	if resp.Error.Code != jsonrpc.BlockedError {
		t.Errorf("error code = %d, want %d", resp.Error.Code, jsonrpc.BlockedError)
	}

	// Verify the .env file was NOT modified
	after, _ := os.ReadFile(filepath.Join(dir, ".env"))
	if string(after) != string(envContent) {
		t.Errorf(".env was modified despite being blocked: %q → %q", envContent, after)
	}
}

func TestE2E_MixedStream(t *testing.T) {
	skipE2E(t)
	dir := setupTestDir(t)

	messages := append(initMessages(),
		// id=2: tools/list (allowed — not tools/call)
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
		// id=3: read .env (BLOCKED)
		fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"%s/.env"}}}`, dir),
		// id=4: read safe.txt (allowed)
		fmt.Sprintf(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"%s/safe.txt"}}}`, dir),
		// id=5: write .env (BLOCKED)
		fmt.Sprintf(`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"%s/.env","content":"STOLEN"}}}`, dir),
	)
	responses := runMCPE2E(t, dir, messages)

	// id=1: initialize — should succeed
	if r := findByID(responses, 1); r == nil || r.Error != nil {
		t.Error("initialize (id=1) should succeed")
	}

	// id=2: tools/list — should succeed
	if r := findByID(responses, 2); r == nil || r.Error != nil {
		t.Error("tools/list (id=2) should succeed")
	}

	// id=3: read .env — should be blocked
	if r := findByID(responses, 3); r == nil {
		t.Error("expected response for blocked .env read (id=3)")
	} else if r.Error == nil {
		t.Error("read .env (id=3) should be blocked")
	} else if r.Error.Code != jsonrpc.BlockedError {
		t.Errorf("read .env error code = %d, want %d", r.Error.Code, jsonrpc.BlockedError)
	}

	// id=4: read safe.txt — should succeed with content
	if r := findByID(responses, 4); r == nil {
		t.Error("expected response for safe.txt read (id=4)")
	} else if r.Error != nil {
		t.Errorf("read safe.txt (id=4) should succeed, got error: %s", r.Error.Message)
	} else if !strings.Contains(string(r.Result), "hello world") {
		t.Errorf("read safe.txt (id=4) missing content, got: %s", string(r.Result))
	}

	// id=5: write .env — should be blocked
	if r := findByID(responses, 5); r == nil {
		t.Error("expected response for blocked .env write (id=5)")
	} else if r.Error == nil {
		t.Error("write .env (id=5) should be blocked")
	} else if r.Error.Code != jsonrpc.BlockedError {
		t.Errorf("write .env error code = %d, want %d", r.Error.Code, jsonrpc.BlockedError)
	}
}
