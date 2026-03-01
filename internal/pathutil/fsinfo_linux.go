//go:build linux

package pathutil

import "golang.org/x/sys/unix"

// caseInsensitiveFS lists filesystem magic numbers (from statfs.f_type) for
// filesystems that are inherently case-insensitive. All constants are from
// golang.org/x/sys/unix.
//
// Note: ext4 with casefold (Linux 5.2+) is case-insensitive but has the same
// magic number as regular ext4. This is a known limitation — ext4-casefold is
// very rare in practice.
var caseInsensitiveFS = map[int64]bool{
	unix.MSDOS_SUPER_MAGIC: true, // vfat / FAT32
	unix.EXFAT_SUPER_MAGIC: true, // exFAT
	unix.CIFS_SUPER_MAGIC:  true, // CIFS/SMB mount
	unix.SMB_SUPER_MAGIC:   true, // older SMB
	unix.SMB2_SUPER_MAGIC:  true, // SMB2/SMB3
}

// DetectFS queries filesystem properties for the volume containing path
// using statfs(2). This is a direct kernel syscall that reports the filesystem
// type — it cannot be fooled by userspace tricks.
//
// The filesystem type is compared against a list of known case-insensitive
// filesystem types (vfat, exFAT, CIFS, SMB). Standard Linux filesystems
// (ext4, btrfs, xfs, zfs) are case-sensitive by default.
func DetectFS(path string) FSInfo {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		// Safe fallback: treat as case-sensitive (Linux default).
		return FSInfo{CaseSensitive: true}
	}
	return FSInfo{CaseSensitive: !caseInsensitiveFS[stat.Type]}
}
