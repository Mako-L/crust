package message

import (
	"strings"
	"testing"

	"github.com/BakeLens/crust/internal/rules"
)

func TestFormatHTTPBlock(t *testing.T) {
	tests := []struct {
		name         string
		result       rules.MatchResult
		wantContains []string
	}{
		{
			name:         "with message",
			result:       rules.MatchResult{Message: "SSH keys are protected", RuleName: "protect-ssh-keys"},
			wantContains: []string{"[Crust]", "Request blocked", "SSH keys are protected"},
		},
		{
			name:         "without message",
			result:       rules.MatchResult{RuleName: "protect-ssh-keys"},
			wantContains: []string{"[Crust]", "Request blocked by rule", "protect-ssh-keys"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatHTTPBlock(tt.result)
			for _, want := range tt.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("FormatHTTPBlock() = %q, want to contain %q", got, want)
				}
			}
		})
	}
}

func TestFormatRemoveWarning(t *testing.T) {
	tests := []struct {
		name         string
		blocked      []BlockedCall
		wantContains []string
	}{
		{
			name: "single blocked call",
			blocked: []BlockedCall{
				{ToolName: "Bash", MatchResult: rules.MatchResult{Message: "Dangerous command"}},
			},
			wantContains: []string{"[Crust]", "Bash", "Dangerous command", "Do not retry"},
		},
		{
			name: "multiple blocked calls",
			blocked: []BlockedCall{
				{ToolName: "Bash", MatchResult: rules.MatchResult{Message: "Blocked rm"}},
				{ToolName: "Read", MatchResult: rules.MatchResult{Message: "Blocked credential read"}},
			},
			wantContains: []string{"[Crust]", "Bash", "Read", "Blocked rm", "Blocked credential read", "Do not retry"},
		},
		{
			name: "blocked call without message",
			blocked: []BlockedCall{
				{ToolName: "Write", MatchResult: rules.MatchResult{}},
			},
			wantContains: []string{"[Crust]", "Write", "Do not retry"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatRemoveWarning(tt.blocked)
			for _, want := range tt.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("FormatRemoveWarning() = %q, want to contain %q", got, want)
				}
			}
		})
	}
}

func TestFormatReplaceDetail(t *testing.T) {
	tests := []struct {
		name   string
		result rules.MatchResult
		want   string
	}{
		{
			name:   "with message",
			result: rules.MatchResult{Message: "Custom block reason", RuleName: "test-rule"},
			want:   "Custom block reason (rule: test-rule)",
		},
		{
			name:   "without message",
			result: rules.MatchResult{RuleName: "test-rule"},
			want:   "blocked by rule: test-rule",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatReplaceDetail(tt.result)
			if got != tt.want {
				t.Errorf("FormatReplaceDetail() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatReplaceInline(t *testing.T) {
	result := rules.MatchResult{Message: "SSH keys are protected", RuleName: "protect-ssh-keys"}
	got := FormatReplaceInline("Bash", result)

	for _, want := range []string{"[Crust]", "Bash", "SSH keys are protected", "protect-ssh-keys", "Do not retry"} {
		if !strings.Contains(got, want) {
			t.Errorf("FormatReplaceInline() = %q, want to contain %q", got, want)
		}
	}
}

func TestFormatReplaceWarning(t *testing.T) {
	blocked := []BlockedCall{
		{ToolName: "Bash", MatchResult: rules.MatchResult{Message: "Blocked rm", RuleName: "block-rm"}},
		{ToolName: "Read", MatchResult: rules.MatchResult{RuleName: "block-read"}},
	}
	got := FormatReplaceWarning(blocked)

	for _, want := range []string{"[Crust]", "Bash", "Read", "Blocked rm", "block-rm", "block-read", "Do not retry"} {
		if !strings.Contains(got, want) {
			t.Errorf("FormatReplaceWarning() = %q, want to contain %q", got, want)
		}
	}
}

func TestFormatJSONRPCBlock(t *testing.T) {
	got := FormatJSONRPCBlock("protect-ssh-keys", "SSH keys are protected")
	for _, want := range []string{"[Crust]", "protect-ssh-keys", "SSH keys are protected", "Do not retry"} {
		if !strings.Contains(got, want) {
			t.Errorf("FormatJSONRPCBlock() = %q, want to contain %q", got, want)
		}
	}
}

func TestFormatDLPBlock(t *testing.T) {
	got := FormatDLPBlock("dlp-api-key", "API key detected")
	for _, want := range []string{"[Crust]", "dlp-api-key", "API key detected"} {
		if !strings.Contains(got, want) {
			t.Errorf("FormatDLPBlock() = %q, want to contain %q", got, want)
		}
	}
	// DLP blocks should NOT contain "Do not retry" (DLP is content-based, retryable with redacted content)
	if strings.Contains(got, "Do not retry") {
		t.Errorf("FormatDLPBlock() should not contain 'Do not retry'")
	}
}
