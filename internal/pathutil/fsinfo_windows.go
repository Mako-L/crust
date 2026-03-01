//go:build windows

package pathutil

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

// DetectFS queries filesystem properties for the volume containing path
// using GetVolumeInformation. This is a direct kernel syscall that reports
// the volume's actual case sensitivity — it cannot be fooled by userspace tricks.
//
// NTFS is case-insensitive by default. Windows 10+ supports per-directory
// case sensitivity, but the volume-level flag reflects the default behavior.
func DetectFS(path string) FSInfo {
	// Extract volume root (e.g., "C:\").
	vol := filepath.VolumeName(path)
	if vol == "" {
		// No volume name — default to case-insensitive (NTFS default).
		return FSInfo{CaseSensitive: false}
	}
	root := vol + `\`

	var flags uint32
	rootPtr, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return FSInfo{CaseSensitive: false}
	}

	err = windows.GetVolumeInformation(
		rootPtr,
		nil, 0, // volume name buffer (not needed)
		nil,    // serial number (not needed)
		nil,    // max component length (not needed)
		&flags, // filesystem flags — this is what we want
		nil, 0, // filesystem name buffer (not needed)
	)
	if err != nil {
		// Safe fallback: NTFS is case-insensitive by default.
		return FSInfo{CaseSensitive: false}
	}

	return FSInfo{
		CaseSensitive: flags&windows.FILE_CASE_SENSITIVE_SEARCH != 0,
	}
}
