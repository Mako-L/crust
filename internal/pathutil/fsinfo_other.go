//go:build !darwin && !windows && !linux && !freebsd

package pathutil

// DetectFS returns a safe default for unsupported platforms.
// Case-sensitive is the safe default — it may cause false negatives in
// rule matching on case-insensitive filesystems, but never allows a bypass.
func DetectFS(_ string) FSInfo {
	return FSInfo{CaseSensitive: true}
}
