// Package pathutil provides shared, security-critical path utilities for Crust.
//
// All path normalization (case folding, drive letter detection, separator handling,
// path prefix checks) is centralized here to prevent security bugs from divergent
// re-implementations across packages. Case sensitivity is detected via direct
// kernel syscalls (not file-creation probes) and cannot be fooled by userspace tricks.
//
// Supported platforms: macOS (APFS/HFS+), Windows (NTFS), Linux (ext4/btrfs/xfs/vfat/CIFS),
// FreeBSD 15+ (UFS/ZFS).
package pathutil

import (
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// FSInfo holds filesystem properties detected via direct syscalls.
// Extensible for future properties (ADS support, hard links, etc.).
type FSInfo struct {
	CaseSensitive bool
}

// Lower returns strings.ToLower(s) if the filesystem is case-insensitive,
// or s unchanged if case-sensitive. Use this instead of manual
// runtime.GOOS == "windows" checks to correctly handle all platforms
// (macOS case-insensitive APFS, Windows NTFS, Linux vfat/CIFS, FreeBSD ZFS).
func (fi FSInfo) Lower(s string) string {
	if fi.CaseSensitive {
		return s
	}
	return strings.ToLower(s)
}

// DefaultFS returns the filesystem properties for $HOME, detected once at first use.
// Safe for concurrent access. Falls back to case-sensitive on error.
//
// Why $HOME: Crust protects local files which are almost always on the same
// volume as the user's home directory. Per-path detection would add I/O overhead
// on every new mount point. Per-home detection runs once with zero ongoing cost.
var DefaultFS = sync.OnceValue(func() FSInfo {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "."
	}
	return DetectFS(home)
})

// ToSlash converts backslashes to forward slashes for consistent cross-platform
// path matching. Wraps filepath.ToSlash.
func ToSlash(path string) string {
	return filepath.ToSlash(path)
}

// IsDriverLetter returns true if c is an ASCII letter (A-Z or a-z).
// Used to detect Windows drive letter prefixes (e.g., C: in "C:/Users").
func IsDriverLetter(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

// IsDrivePath returns true if path starts with a Windows drive letter prefix
// (e.g., "C:/", "c:\", "D:"). Recognizes both forward and back slashes.
func IsDrivePath(p string) bool {
	if len(p) < 2 {
		return false
	}
	return IsDriverLetter(p[0]) && p[1] == ':'
}

// CleanPath cleans the path by resolving "..", removing duplicate slashes, etc.
// Always returns forward slashes for consistent cross-platform matching.
//
// On Windows: preserves drive letter prefix (e.g., "C:"), collapses leading "//"
// (treated as redundant, not UNC). Uses path.Clean (not filepath.Clean) to avoid
// mangling reserved names (CON, PRN, NUL) and UNC path confusion.
//
// On other platforms: uses path.Clean which always uses forward slashes and does
// not interpret "//" as a Windows UNC path prefix.
func CleanPath(p string) string {
	if p == "" {
		return ""
	}

	// Ensure forward slashes before cleaning.
	p = filepath.ToSlash(p)

	if runtime.GOOS == "windows" {
		// Collapse leading duplicate slashes — agents send Unix-style paths
		// where "//" is a redundant slash, not a Windows UNC prefix.
		for len(p) > 1 && p[0] == '/' && p[1] == '/' {
			p = p[1:]
		}
		// Extract drive letter prefix (e.g., "C:") and use path.Clean for the
		// rest to get correct ".." resolution without reserved-name mangling.
		// filepath.VolumeName also recognizes UNC/NT paths (//??, \\server\share)
		// which we don't want to handle specially for agent-provided paths.
		vol := filepath.VolumeName(p)
		if len(vol) != 2 || vol[1] != ':' || !IsDriverLetter(vol[0]) {
			vol = "" // Not a drive letter — treat as regular path
		}
		rest := p[len(vol):]
		cleaned := path.Clean(rest)
		// Ensure absolute paths stay absolute
		if strings.HasPrefix(rest, "/") && !strings.HasPrefix(cleaned, "/") {
			cleaned = "/" + cleaned
		}
		return vol + cleaned
	}

	// Unix: use path.Clean which always uses forward slashes.
	cleaned := path.Clean(p)

	// Ensure absolute paths stay absolute
	// (path.Clean might produce "." for some edge cases)
	if strings.HasPrefix(p, "/") && !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}

	return cleaned
}

// HasPathPrefix checks if path starts with dir as a proper path prefix.
// Returns true if path == dir OR path starts with dir followed by a separator.
// Prevents false prefix matches like dir="/rules" matching path="/rules-backup".
// Uses filepath.Separator for native-separator paths (from filepath.Abs/Clean).
func HasPathPrefix(p, dir string) bool {
	if p == dir {
		return true
	}
	return strings.HasPrefix(p, dir+string(filepath.Separator))
}

// StripFileURIDriveLetter strips a leading "/" before a Windows drive letter
// in parsed file:// URI paths. file:///C:/foo → url.Parse → Path="/C:/foo" →
// this function returns "C:/foo". Non-drive-letter paths are returned unchanged.
//
// Examples:
//
//	"/C:/Users/file.txt" → "C:/Users/file.txt"
//	"/c:/foo"            → "c:/foo"
//	"/unix/path"         → "/unix/path" (unchanged)
//	""                   → ""
func StripFileURIDriveLetter(p string) string {
	// Pattern: "/X:" where X is a drive letter
	if len(p) >= 3 && p[0] == '/' && IsDriverLetter(p[1]) && p[2] == ':' {
		return p[1:]
	}
	return p
}
