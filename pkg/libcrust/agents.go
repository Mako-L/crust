//go:build libcrust

package libcrust

import "github.com/BakeLens/crust/internal/agentdetect"

// DetectAgents scans for running AI agent processes and returns their status as JSON.
func DetectAgents() string {
	agents := agentdetect.Detect()
	if agents == nil {
		return "[]"
	}
	return mustJSON(agents)
}
