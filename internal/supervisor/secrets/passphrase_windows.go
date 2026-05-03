//go:build windows

package secrets

import "os"

// checkKeyfileOwner is a no-op stub on Windows. The unix
// implementation in passphrase_unix.go uses syscall.Stat_t.Uid which
// has no meaningful Windows equivalent (NT ACLs are out of scope per
// the spec). Windows is a developer-build target only — gc does not
// ship Windows binaries — so the stub keeps the package compiling
// without claiming any security guarantee on Windows.
func checkKeyfileOwner(path string, info os.FileInfo) error {
	return nil
}
