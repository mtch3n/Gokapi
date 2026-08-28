//go:build !unix

package logging

import "testing"

// limitAuditFileSize is not implementable on non-unix platforms (no RLIMIT_FSIZE), so the test
// that depends on it is skipped there instead.
func limitAuditFileSize(t *testing.T, dir string, extraBytes int64) func() {
	t.Helper()
	t.Skip("RLIMIT_FSIZE is only available on unix platforms")
	return func() {}
}
