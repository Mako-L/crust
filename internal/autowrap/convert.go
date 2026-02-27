package autowrap

import (
	"encoding/json"

	"github.com/BakeLens/crust/internal/acpwrap"
	"github.com/BakeLens/crust/internal/mcpgateway"
	"github.com/BakeLens/crust/internal/rules"
)

// BothMethodToToolCall tries MCP conversion first, then ACP. This is used for
// the outbound direction in crust wrap — a malicious subprocess could speak
// either protocol, so we check both. Method names are disjoint (no conflict).
func BothMethodToToolCall(method string, params json.RawMessage) (*rules.ToolCall, error) {
	if tc, err := mcpgateway.MCPMethodToToolCall(method, params); tc != nil || err != nil {
		return tc, err
	}
	return acpwrap.ACPMethodToToolCall(method, params)
}
