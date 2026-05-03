//go:build unix

package secrets

import (
	"fmt"
	"os"
	"syscall"
)

func checkKeyfileOwner(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		// Non-unix or test stub — skip ownership check.
		return nil
	}
	if int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf(
			"passphrase file %s is owned by uid %d, but current process euid is %d; refuse",
			path, stat.Uid, os.Geteuid(),
		)
	}
	return nil
}
