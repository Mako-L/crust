//go:build freebsd

package pathutil

import "golang.org/x/sys/unix"

// pcCaseInsensitive mirrors FreeBSD _PC_CASE_INSENSITIVE (70) from sys/sys/unistd.h.
// Not exported by golang.org/x/sys/unix. Requires FreeBSD 15+.
//
// pathconf(path, pcCaseInsensitive) returns:
//   - 1 if the filesystem is case-insensitive (e.g., ZFS casesensitivity=insensitive, msdosfs)
//   - 0 if the filesystem is case-sensitive (e.g., UFS, ZFS default)
const pcCaseInsensitive = 70

// DetectFS queries filesystem properties for the volume containing path
// using pathconf(2). This is a direct kernel VFS query that reports the
// filesystem's actual case sensitivity — it cannot be fooled by userspace tricks.
func DetectFS(path string) FSInfo {
	val, err := unix.Pathconf(path, pcCaseInsensitive)
	if err != nil {
		// Safe fallback: treat as case-sensitive (UFS/ZFS default).
		return FSInfo{CaseSensitive: true}
	}
	// val == 1 means case-insensitive, val == 0 means case-sensitive
	return FSInfo{CaseSensitive: val == 0}
}
