// Package message provides centralized formatting for block messages
// delivered to AI agents across all Crust delivery paths (HTTP, SSE, JSON-RPC).
package message

import (
	"fmt"
	"strings"

	"github.com/BakeLens/crust/internal/rules"
)

const prefix = "[Crust]"
const doNotRetry = "Do not retry — this action is permanently denied."

// BlockedCall holds info about a single blocked tool call for formatting.
type BlockedCall struct {
	ToolName    string
	MatchResult rules.MatchResult
}

// FormatHTTPBlock formats the block message for HTTP 403 (L0).
func FormatHTTPBlock(result rules.MatchResult) string {
	if result.Message != "" {
		return prefix + " Request blocked: " + result.Message
	}
	return prefix + " Request blocked by rule: " + result.RuleName
}

// FormatRemoveWarning formats the aggregate warning for HTTP L1 remove mode.
// Also used by SSE streaming injection.
func FormatRemoveWarning(blocked []BlockedCall) string {
	var sb strings.Builder
	sb.WriteString(prefix + " The following tool calls were blocked:\n")
	for _, bc := range blocked {
		sb.WriteString("- " + bc.ToolName)
		if bc.MatchResult.Message != "" {
			sb.WriteString(": " + bc.MatchResult.Message)
		}
		sb.WriteString("\n")
	}
	sb.WriteString(doNotRetry + "\n")
	return sb.String()
}

// FormatReplaceInline formats a single inline block for replace mode.
// Used when replacing a tool_use block with a text block.
func FormatReplaceInline(toolName string, result rules.MatchResult) string {
	msg := FormatReplaceDetail(result)
	return fmt.Sprintf("\n%s Tool '%s' blocked: %s\n%s\n",
		prefix, toolName, msg, doNotRetry)
}

// FormatReplaceDetail formats the detail for a single replaced tool call.
func FormatReplaceDetail(result rules.MatchResult) string {
	if result.Message != "" {
		return result.Message + " (rule: " + result.RuleName + ")"
	}
	return "blocked by rule: " + result.RuleName
}

// FormatReplaceWarning formats the aggregate warning for replace mode (OpenAI Chat).
func FormatReplaceWarning(blocked []BlockedCall) string {
	var sb strings.Builder
	sb.WriteString(prefix + " The following tool calls were blocked:\n")
	for _, bc := range blocked {
		fmt.Fprintf(&sb, "- %s: %s\n", bc.ToolName, FormatReplaceDetail(bc.MatchResult))
	}
	sb.WriteString(doNotRetry + "\n")
	return sb.String()
}

// FormatJSONRPCBlock formats the error message for JSON-RPC -32001 responses (ACP/MCP).
func FormatJSONRPCBlock(ruleName, ruleMessage string) string {
	return fmt.Sprintf("%s Blocked by rule %q: %s %s",
		prefix, ruleName, ruleMessage, doNotRetry)
}

// FormatDLPBlock formats the error message for DLP-triggered blocks.
func FormatDLPBlock(ruleName, ruleMessage string) string {
	return fmt.Sprintf("%s Blocked by rule %q: %s",
		prefix, ruleName, ruleMessage)
}
