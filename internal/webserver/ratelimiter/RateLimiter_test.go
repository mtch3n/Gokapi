package ratelimiter

import (
	"testing"
	"time"
)

// TestAllowUnsealBurstThenRejects is the failing-first test for the fix to the unauthenticated
// POST /api/unseal endpoint: WaitOnUnseal used to block the calling goroutine (WaitN) until the
// rate limiter allowed the request, never rejecting outright. That let an attacker hold many
// connections open, each eventually running an expensive scrypt derivation, with no way for the
// caller to answer 429 promptly. AllowUnseal must instead be non-blocking: twenty attempts from
// the same IP go through immediately (matching the existing burst), and the 21st is rejected
// immediately rather than delayed - checked here by asserting the call returns in well under the
// 2-second refill period, not merely that it eventually returns.
func TestAllowUnsealBurstThenRejects(t *testing.T) {
	const ip = "203.0.113.10"

	for i := 0; i < 20; i++ {
		if !AllowUnseal(ip) {
			t.Fatalf("attempt %d: expected burst allowance, got rejected", i+1)
		}
	}

	start := time.Now()
	allowed := AllowUnseal(ip)
	elapsed := time.Since(start)

	if allowed {
		t.Fatal("expected the 21st attempt within the burst window to be rejected")
	}
	if elapsed > 100*time.Millisecond {
		t.Fatalf("AllowUnseal blocked for %v instead of rejecting immediately", elapsed)
	}
}

// TestAllowUnsealIsPerIP is the per-IP-tracking half of the same requirement: one IP exhausting
// its burst must not affect a different IP, which is exactly the existing WaitOnDownloadPassword
// bucketing (see failedDownloadPasswordLimiter) that AllowUnseal is expected to keep for the
// separate failedUnsealLimiter bucket.
func TestAllowUnsealIsPerIP(t *testing.T) {
	const busyIP = "203.0.113.20"
	const freshIP = "203.0.113.21"

	for i := 0; i < 20; i++ {
		if !AllowUnseal(busyIP) {
			t.Fatalf("attempt %d against busyIP: expected burst allowance, got rejected", i+1)
		}
	}
	if AllowUnseal(busyIP) {
		t.Fatal("expected busyIP to be rejected after exhausting its burst")
	}
	if !AllowUnseal(freshIP) {
		t.Fatal("expected freshIP to still have its own, untouched burst")
	}
}

// TestAllowUnsealRefillsOverTime confirms AllowUnseal is a genuine rate limiter and not a
// one-shot lockout: once the refill period (2 seconds, matching the previous WaitN(ctx, 2)
// behaviour) has passed, a further attempt is allowed again.
func TestAllowUnsealRefillsOverTime(t *testing.T) {
	const ip = "203.0.113.30"

	for i := 0; i < 20; i++ {
		if !AllowUnseal(ip) {
			t.Fatalf("attempt %d: expected burst allowance, got rejected", i+1)
		}
	}
	if AllowUnseal(ip) {
		t.Fatal("expected rejection immediately after exhausting the burst")
	}

	time.Sleep(2100 * time.Millisecond)

	if !AllowUnseal(ip) {
		t.Fatal("expected a fresh token to be available after the refill period")
	}
}
