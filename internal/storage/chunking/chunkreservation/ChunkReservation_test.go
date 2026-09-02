package chunkreservation

import (
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// resetStateBlockCleanup resets the package-level state between tests.
func resetStateBlockCleanup() {
	reservationMutex.Lock()
	reservedChunks = make(map[string]map[string]reservation)
	runGcOnce.Do(func() {
		//prevent NewIfUnder from spawning the cleanup goroutine
	})
	reservationMutex.Unlock()
}

// newUnlimited creates a reservation with no cap, for tests that only care about reservation
// bookkeeping and not about NewIfUnder's limit behaviour (covered separately below).
func newUnlimited(id string) string {
	uuid, _ := NewIfUnder(id, -1)
	return uuid
}

// TestNewIfUnder_ReturnsNonEmptyUuid checks that newUnlimited (backed by NewIfUnder) returns a non-empty uuid string.
func TestNewIfUnder_ReturnsNonEmptyUuid(t *testing.T) {
	resetStateBlockCleanup()
	uuid := newUnlimited("file1")
	if uuid == "" {
		t.Error("expected non-empty uuid, got empty string")
	}
}

// TestNewIfUnder_UuidLength checks that the generated uuid has the expected length (32 chars).
func TestNewIfUnder_UuidLength(t *testing.T) {
	resetStateBlockCleanup()
	uuid := newUnlimited("file1")
	if len(uuid) != 32 {
		t.Errorf("expected uuid length 32, got %d", len(uuid))
	}
}

// TestNewIfUnder_UniqueUuids checks that two calls produce different uuids.
func TestNewIfUnder_UniqueUuids(t *testing.T) {
	resetStateBlockCleanup()
	uuid1 := newUnlimited("file1")
	uuid2 := newUnlimited("file1")
	if uuid1 == uuid2 {
		t.Error("expected unique uuids, got identical values")
	}
}

// TestNewIfUnder_StoresReservation checks that newUnlimited (backed by NewIfUnder) stores the reservation in the map.
func TestNewIfUnder_StoresReservation(t *testing.T) {
	resetStateBlockCleanup()
	uuid := newUnlimited("file1")
	reservationMutex.RLock()
	_, ok := reservedChunks["file1"][uuid]
	reservationMutex.RUnlock()
	if !ok {
		t.Error("expected reservation to be stored in map")
	}
}

// TestNewIfUnder_ExpiryIsInFuture checks that the reservation expiry is in the future.
func TestNewIfUnder_ExpiryIsInFuture(t *testing.T) {
	resetStateBlockCleanup()
	now := time.Now().Unix()
	uuid := newUnlimited("file1")
	reservationMutex.RLock()
	expiry := reservedChunks["file1"][uuid].Expiry
	reservationMutex.RUnlock()
	if expiry <= now {
		t.Errorf("expected expiry > %d, got %d", now, expiry)
	}
}

// TestNewIfUnder_ExpiryMatchesConstant checks that the expiry is set to now + timeReservationWithoutUpload.
func TestNewIfUnder_ExpiryMatchesConstant(t *testing.T) {
	resetStateBlockCleanup()
	now := time.Now().Unix()
	uuid := newUnlimited("file1")
	reservationMutex.RLock()
	expiry := reservedChunks["file1"][uuid].Expiry
	reservationMutex.RUnlock()
	expected := now + timeReservationWithoutUpload
	// Allow 1 second of slack for execution time.
	if expiry < expected || expiry > expected+1 {
		t.Errorf("expected expiry ~%d, got %d", expected, expiry)
	}
}

// TestNewIfUnder_UuidStoredOnReservation checks that the uuid field on the reservation matches the returned uuid.
func TestNewIfUnder_UuidStoredOnReservation(t *testing.T) {
	resetStateBlockCleanup()
	uuid := newUnlimited("file1")
	reservationMutex.RLock()
	r := reservedChunks["file1"][uuid]
	reservationMutex.RUnlock()
	if r.Uuid != uuid {
		t.Errorf("expected reservation uuid %q, got %q", uuid, r.Uuid)
	}
}

// TestNewIfUnder_InitialisesMapForNewId checks that newUnlimited (backed by NewIfUnder) creates the inner map for a new file id.
func TestNewIfUnder_InitialisesMapForNewId(t *testing.T) {
	resetStateBlockCleanup()
	newUnlimited("newfile")
	reservationMutex.RLock()
	_, ok := reservedChunks["newfile"]
	reservationMutex.RUnlock()
	if !ok {
		t.Error("expected inner map to be initialised for new file id")
	}
}

// TestNewIfUnder_MultipleIdsAreIndependent checks that reservations for different ids don't interfere.
func TestNewIfUnder_MultipleIdsAreIndependent(t *testing.T) {
	resetStateBlockCleanup()
	newUnlimited("fileA")
	newUnlimited("fileB")
	newUnlimited("fileB")
	if GetCount("fileA") != 1 {
		t.Errorf("expected 1 reservation for fileA, got %d", GetCount("fileA"))
	}
	if GetCount("fileB") != 2 {
		t.Errorf("expected 2 reservations for fileB, got %d", GetCount("fileB"))
	}
}

// TestGetCount_ReturnsZeroForUnknownId checks that GetCount returns 0 for an unknown file id.
func TestGetCount_ReturnsZeroForUnknownId(t *testing.T) {
	resetStateBlockCleanup()
	if count := GetCount("unknown"); count != 0 {
		t.Errorf("expected 0, got %d", count)
	}
}

// TestGetCount_ReturnsCorrectCount checks that GetCount reflects the number of active reservations.
func TestGetCount_ReturnsCorrectCount(t *testing.T) {
	resetStateBlockCleanup()
	newUnlimited("file1")
	newUnlimited("file1")
	newUnlimited("file1")
	if count := GetCount("file1"); count != 3 {
		t.Errorf("expected 3, got %d", count)
	}
}

// TestSetComplete_RemovesReservation checks that SetComplete deletes the reservation.
func TestSetComplete_RemovesReservation(t *testing.T) {
	resetStateBlockCleanup()
	uuid := newUnlimited("file1")
	SetComplete("file1", uuid)
	reservationMutex.RLock()
	_, ok := reservedChunks["file1"][uuid]
	reservationMutex.RUnlock()
	if ok {
		t.Error("expected reservation to be removed after SetComplete")
	}
}

// TestSetComplete_DecreasesCount checks that GetCount decreases after SetComplete.
func TestSetComplete_DecreasesCount(t *testing.T) {
	resetStateBlockCleanup()
	uuid := newUnlimited("file1")
	newUnlimited("file1")
	SetComplete("file1", uuid)
	if count := GetCount("file1"); count != 1 {
		t.Errorf("expected count 1 after SetComplete, got %d", count)
	}
}

// TestSetComplete_UnknownIdDoesNotPanic checks that SetComplete is safe for unknown ids.
func TestSetComplete_UnknownIdDoesNotPanic(t *testing.T) {
	resetStateBlockCleanup()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("SetComplete panicked on unknown id: %v", r)
		}
	}()
	SetComplete("unknown-id", "unknown-uuid")
}

// TestSetUploading_ReturnsTrueForValidReservation checks the happy path.
func TestSetUploading_ReturnsTrueForValidReservation(t *testing.T) {
	resetStateBlockCleanup()
	uuid := newUnlimited("file1")
	if !SetUploading("file1", uuid) {
		t.Error("expected SetUploading to return true for a valid reservation")
	}
}

// TestSetUploading_ExtendsExpiry checks that SetUploading extends the expiry to the upload constant.
func TestSetUploading_ExtendsExpiry(t *testing.T) {
	resetStateBlockCleanup()
	now := time.Now().Unix()
	uuid := newUnlimited("file1")
	SetUploading("file1", uuid)
	reservationMutex.RLock()
	expiry := reservedChunks["file1"][uuid].Expiry
	reservationMutex.RUnlock()
	expected := now + timeReservationWithUpload
	if expiry < expected || expiry > expected+1 {
		t.Errorf("expected expiry ~%d after SetUploading, got %d", expected, expiry)
	}
}

// TestSetUploading_ReturnsFalseForUnknownId checks that SetUploading returns false for unknown file id.
func TestSetUploading_ReturnsFalseForUnknownId(t *testing.T) {
	resetStateBlockCleanup()
	if SetUploading("unknown-id", "some-uuid") {
		t.Error("expected SetUploading to return false for unknown file id")
	}
}

// TestSetUploading_ReturnsFalseForUnknownUuid checks that SetUploading returns false for unknown uuid.
func TestSetUploading_ReturnsFalseForUnknownUuid(t *testing.T) {
	resetStateBlockCleanup()
	newUnlimited("file1")
	if SetUploading("file1", "not-a-real-uuid") {
		t.Error("expected SetUploading to return false for unknown uuid")
	}
}

// TestSetUploading_ReturnsFalseForExpiredReservation checks that an expired reservation is rejected.
func TestSetUploading_ReturnsFalseForExpiredReservation(t *testing.T) {
	resetStateBlockCleanup()
	uuid := "expired-uuid"
	reservationMutex.Lock()
	reservedChunks["file1"] = map[string]reservation{
		uuid: {Uuid: uuid, Expiry: time.Now().Unix() - 1},
	}
	reservationMutex.Unlock()
	if SetUploading("file1", uuid) {
		t.Error("expected SetUploading to return false for expired reservation")
	}
}

// TestCleanup_RemovesExpiredReservations checks that cleanUp removes expired entries.
func TestCleanup_RemovesExpiredReservations(t *testing.T) {
	resetStateBlockCleanup()
	reservationMutex.Lock()
	reservedChunks["file1"] = map[string]reservation{
		"expired": {Uuid: "expired", Expiry: time.Now().Unix() - 10},
		"valid":   {Uuid: "valid", Expiry: time.Now().Unix() + 300},
	}
	reservationMutex.Unlock()

	cleanUp(false)

	reservationMutex.RLock()
	_, expiredExists := reservedChunks["file1"]["expired"]
	_, validExists := reservedChunks["file1"]["valid"]
	reservationMutex.RUnlock()

	if expiredExists {
		t.Error("expected expired reservation to be removed by cleanUp")
	}
	if !validExists {
		t.Error("expected valid reservation to survive cleanUp")
	}
}

// TestCleanup_EmptyMapDoesNotPanic checks that cleanUp on an empty map does not panic.
func TestCleanup_EmptyMapDoesNotPanic(t *testing.T) {
	resetStateBlockCleanup()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("cleanUp panicked on empty map: %v", r)
		}
	}()
	cleanUp(false)
}

// TestCleanup_PeriodicRunsAfterFiveMinutes verifies that the periodic cleanup goroutine
// re-runs after 5 minutes. The fake clock advances instantly — no real waiting.
func TestCleanup_PeriodicRunsAfterFiveMinutes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		resetStateBlockCleanup()

		// Insert a reservation that expires in 2 minutes.
		reservationMutex.Lock()
		reservedChunks["file1"] = map[string]reservation{
			"will-expire": {Uuid: "will-expire", Expiry: time.Now().Unix() + 120},
		}
		reservationMutex.Unlock()

		// Run one non-periodic pass; token still valid so it should survive.
		cleanUp(false)
		synctest.Wait()

		reservationMutex.RLock()
		_, stillThere := reservedChunks["file1"]["will-expire"]
		reservationMutex.RUnlock()
		if !stillThere {
			t.Error("expected reservation to still be present before expiry")
		}

		// Advance fake clock past the 2-minute expiry and the 5-minute cleanup interval.
		time.Sleep(6 * time.Minute)
		cleanUp(false)
		synctest.Wait()

		reservationMutex.RLock()
		_, stillThere = reservedChunks["file1"]["will-expire"]
		reservationMutex.RUnlock()
		if stillThere {
			t.Error("expected reservation to be removed after periodic cleanup ran")
		}
	})
}

// TestNewIfUnder_RejectsAtLimit checks that a call past the limit is rejected and returns an
// empty uuid, once existing reservations have reached it.
func TestNewIfUnder_RejectsAtLimit(t *testing.T) {
	resetStateBlockCleanup()
	uuid, ok := NewIfUnder("file1", 1)
	if !ok || uuid == "" {
		t.Fatalf("expected first reservation to succeed, got ok=%v uuid=%q", ok, uuid)
	}
	uuid2, ok2 := NewIfUnder("file1", 1)
	if ok2 || uuid2 != "" {
		t.Errorf("expected second reservation to be rejected at limit 1, got ok=%v uuid=%q", ok2, uuid2)
	}
}

// TestNewIfUnder_NegativeLimitIsUnlimited checks that a negative limit never rejects, the
// behaviour apiChunkReserve relies on for a file request with no MaxFiles cap.
func TestNewIfUnder_NegativeLimitIsUnlimited(t *testing.T) {
	resetStateBlockCleanup()
	for i := 0; i < 50; i++ {
		uuid, ok := NewIfUnder("file1", -1)
		if !ok || uuid == "" {
			t.Fatalf("attempt %d: expected unlimited reservation to succeed, got ok=%v uuid=%q", i, ok, uuid)
		}
	}
	if count := GetCount("file1"); count != 50 {
		t.Errorf("expected 50 reservations, got %d", count)
	}
}

// TestNewIfUnder_ConcurrentReservesNeverExceedLimit is the failing-first regression test for the
// check-then-act race this function replaces: a separate GetCount then New let concurrent callers
// all read the count below the limit before any of them had committed a reservation, so all of
// them could succeed regardless of the limit. NewIfUnder holds the mutex across both the count
// check and the insert, so no matter how much concurrency is thrown at it, at most `limit`
// reservations must ever be created for the same id.
func TestNewIfUnder_ConcurrentReservesNeverExceedLimit(t *testing.T) {
	resetStateBlockCleanup()
	const limit = 5
	const concurrency = 100

	var wg sync.WaitGroup
	var succeeded int64
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			if _, ok := NewIfUnder("capped-file", limit); ok {
				atomic.AddInt64(&succeeded, 1)
			}
		}()
	}
	wg.Wait()

	if succeeded > limit {
		t.Errorf("expected at most %d successful reservations out of %d concurrent attempts, got %d", limit, concurrency, succeeded)
	}
	if count := GetCount("capped-file"); count != int(succeeded) {
		t.Errorf("expected stored reservation count %d to match successful count %d", count, succeeded)
	}
}
