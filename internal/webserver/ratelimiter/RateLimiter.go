package ratelimiter

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/forceu/gokapi/internal/logging"
	"golang.org/x/time/rate"
)

var newUuidLimiter = newLimiter()
var failedLoginLimiter = newLimiter()
var failedIdLimiter = newLimiter()
var failedDownloadPasswordLimiter = newLimiter()
var failedApiKeyLimiter = newLimiter()
var failedUnsealLimiter = newLimiter()

// isUnitTest must be false and is only set to true for running test units
// If true, rate limiting is disabled
var isUnitTest = false

type limiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// SetUnitTestMode disables all rate limiting
// This is only used for running unit tests
func SetUnitTestMode(enabled bool) {
	fmt.Println("Rate limiting disabled for unit tests")
	isUnitTest = enabled
}

type store struct {
	mu          sync.Mutex
	limiters    map[string]*limiterEntry
	cleanupOnce sync.Once
}

func newLimiter() *store {
	return &store{
		limiters: make(map[string]*limiterEntry),
	}
}

// WaitOnLogin blocks the current goroutine until the rate limiter allows a request
// Three attempts without limiting, thereafter one attempt every 3 seconds
func WaitOnLogin(ip string) {
	_ = failedLoginLimiter.Get(ip, 1, 9).WaitN(context.Background(), 3)
}

// WaitOnApiAuthentication blocks the current goroutine until the rate limiter allows a request
// 200 attempts without limiting, thereafter one attempt every second
func WaitOnApiAuthentication(ip string) {
	_ = failedApiKeyLimiter.Get(ip, 1, 200).WaitN(context.Background(), 1)
}

// WaitOnDownloadPassword blocks the current goroutine until the rate limiter allows a request
// Ten attempts without limiting, thereafter one attempt every 2 seconds
func WaitOnDownloadPassword(ip string) {
	_ = failedDownloadPasswordLimiter.Get(ip, 1, 20).WaitN(context.Background(), 2)
}

// AllowUnseal reports whether an unseal attempt from ip is allowed right now, without blocking.
// Twenty attempts without limiting, thereafter one allowed every 2 seconds; unlike
// WaitOnDownloadPassword this never blocks the caller - POST /api/unseal drives scrypt with
// N=2^20 (~1 GiB RAM, 1-2s CPU) per attempt, so a caller that exceeds the burst must be turned
// away with 429 immediately rather than parked on WaitN, which would hold the goroutine and
// connection open for no benefit: an attacker can simply open more connections instead of waiting
// on one. See also the process-wide derivation semaphore in package encryption, which bounds
// actual scrypt concurrency regardless of how many IPs or connections are used.
func AllowUnseal(ip string) bool {
	return failedUnsealLimiter.Get(ip, 1, 20).Allow()
}

// WaitOnFailedId blocks the current goroutine until the rate limiter allows a request
// Ten failed attempts without limiting, thereafter one attempt every second
func WaitOnFailedId(r *http.Request) {
	ip := logging.GetIpAddress(r)
	_ = failedIdLimiter.Get(ip, 1, 10).Wait(context.Background())
}

// IsAllowedNewUuid returns true if a new uuid is not rate-limited
// Four initial requests are allowed without rate limiting, thereafter one every second
func IsAllowedNewUuid(key string) bool {
	return newUuidLimiter.Get(key, 1, 4).Allow()
}

// Get returns the rate limiter for the given key
func (s *store) Get(key string, r rate.Limit, burst int) *rate.Limiter {
	if isUnitTest {
		return rate.NewLimiter(r, burst)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.limiters[key]
	if !ok {
		e = &limiterEntry{
			limiter: rate.NewLimiter(r, burst),
		}
	}

	e.lastSeen = time.Now()
	s.limiters[key] = e
	s.StartCleanup(12 * time.Hour)
	return e.limiter
}

// StartCleanup starts a goroutine that continuously cleans up old entries from the store
func (s *store) StartCleanup(maxIdle time.Duration) {
	go s.cleanupOnce.Do(
		func() {
			ticker := time.NewTicker(30 * time.Minute)
			for range ticker.C {
				now := time.Now()
				s.mu.Lock()
				for k, v := range s.limiters {
					if now.Sub(v.lastSeen) > maxIdle {
						delete(s.limiters, k)
					}
				}
				s.mu.Unlock()
			}
		})
}
