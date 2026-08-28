//go:build unix

package logging

import (
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/forceu/gokapi/internal/test"
)

// limitAuditFileSize caps the OS-level maximum size of the audit file in dir to its current size
// plus extraBytes, using RLIMIT_FSIZE, so that a write attempting to grow the file past that
// point fails with EFBIG instead of the process being killed - SIGXFSZ (which a write past the
// limit raises by default) is ignored for the duration of the test. It returns a func that
// restores both the original limit and signal disposition; callers must call it (defer) so later
// tests are not affected by process-wide state this changes.
func limitAuditFileSize(t *testing.T, dir string, extraBytes int64) func() {
	t.Helper()

	info, err := os.Stat(filepath.Join(dir, "audit.jsonl"))
	test.IsNil(t, err)

	var original syscall.Rlimit
	test.IsNil(t, syscall.Getrlimit(syscall.RLIMIT_FSIZE, &original))

	limited := syscall.Rlimit{
		Cur: uint64(info.Size() + extraBytes),
		Max: original.Max,
	}
	test.IsNil(t, syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limited))
	signal.Ignore(syscall.SIGXFSZ)

	return func() {
		_ = syscall.Setrlimit(syscall.RLIMIT_FSIZE, &original)
		signal.Reset(syscall.SIGXFSZ)
	}
}
