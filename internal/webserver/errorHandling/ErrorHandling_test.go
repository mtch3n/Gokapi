//go:build test

package errorHandling

import (
	"testing"

	"github.com/forceu/gokapi/internal/test"
)

// TestTokensMapIsBounded reproduces the unauthenticated memory exhaustion finding: every call to
// redirectToError (reached from every /pubapi/* handler via queryUrl, on nothing more than a
// missing or too-short id - no rate limiter previously sat in front of it) inserted into the
// package-level tokens map with a 5 minute TTL but no cap and, previously, only an hourly
// cleanup. Flooding it with distinct tokens must not grow the map past maxTokens.
func TestTokensMapIsBounded(t *testing.T) {
	mutex.Lock()
	tokens = make(map[string]DisplayedError)
	mutex.Unlock()

	w, r := test.GetRecorder("GET", "/error", nil, nil, nil)
	for i := 0; i < maxTokens+500; i++ {
		RedirectToErrorPage(w, r, "title", "message", WidthDefault)
	}

	mutex.RLock()
	size := len(tokens)
	mutex.RUnlock()

	if size > maxTokens {
		t.Errorf("Expected tokens map to be bounded at %d entries, got %d", maxTokens, size)
	}
}
