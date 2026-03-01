//go:build darwin

package pathutil

import "golang.org/x/sys/unix"

// pcCaseSensitive mirrors Darwin _PC_CASE_SENSITIVE (11) from <sys/unistd.h>.
// Not exported by golang.org/x/sys/unix.
//
// pathconf(path, pcCaseSensitive) returns:
//   - 1 if the volume is case-sensitive (e.g., case-sensitive APFS)
//   - 0 if the volume is case-insensitive (e.g., default APFS, HFS+)
const pcCaseSensitive = 11

// DetectFS queries filesystem properties for the volume containing path
// using pathconf(2). This is a direct kernel syscall that reports the
// volume's actual case sensitivity — it cannot be fooled by FUSE or
// userspace filesystem tricks.
func DetectFS(path string) FSInfo {
	val, err := unix.Pathconf(path, pcCaseSensitive)
	if err != nil {
		// Safe fallback: treat as case-sensitive (may cause false negatives
		// in rule matching, but never allows a bypass).
		return FSInfo{CaseSensitive: true}
	}
	return FSInfo{CaseSensitive: val == 1}
}
