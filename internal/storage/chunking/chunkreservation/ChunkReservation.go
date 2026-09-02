package chunkreservation

import (
	"sync"
	"time"

	"github.com/forceu/gokapi/internal/helper"
)

var reservedChunks = make(map[string]map[string]reservation)
var reservationMutex sync.RWMutex
var runGcOnce = sync.Once{}

const timeReservationWithoutUpload = 4 * 60
const timeReservationWithUpload = 23 * 60 * 60

type reservation struct {
	Uuid   string
	Expiry int64
}

// GetCount returns the number of chunks reserved for the given file request
func GetCount(id string) int {
	reservationMutex.RLock()
	defer reservationMutex.RUnlock()
	length := len(reservedChunks[id])
	return length
}

// NewIfUnder creates a new chunk reservation for id, unless limit reservations are already held
// for it. The count and the creation happen under a single lock acquisition, so concurrent
// callers cannot all observe a count below limit before any of them commits - unlike a separate
// GetCount then New, which race and can all succeed. A negative limit means no cap is enforced.
// Returns the new reservation's uuid and true, or an empty string and false if id is already at
// limit.
func NewIfUnder(id string, limit int) (string, bool) {
	reservationMutex.Lock()
	defer reservationMutex.Unlock()

	if limit >= 0 && len(reservedChunks[id]) >= limit {
		return "", false
	}

	uuid := helper.GenerateRandomString(32)
	if reservedChunks[id] == nil {
		reservedChunks[id] = make(map[string]reservation)
	}
	reservedChunks[id][uuid] = reservation{
		Uuid:   uuid,
		Expiry: time.Now().Unix() + timeReservationWithoutUpload,
	}

	runGcOnce.Do(func() { go cleanUp(true) })
	return uuid, true
}

// SetComplete marks a chunk as complete or cancelled
func SetComplete(id, uuid string) {
	reservationMutex.Lock()
	delete(reservedChunks[id], uuid)
	reservationMutex.Unlock()
}

// SetUploading marks a chunk as uploading and extends the reservation time
func SetUploading(id string, uuid string) bool {
	reservationMutex.Lock()
	defer reservationMutex.Unlock()

	if reservedChunks[id] == nil {
		return false
	}
	chunk, ok := reservedChunks[id][uuid]
	if !ok {
		return false
	}
	if chunk.Expiry < time.Now().Unix() {
		return false
	}
	chunk.Expiry = time.Now().Unix() + timeReservationWithUpload
	reservedChunks[id][uuid] = chunk
	return true
}

func cleanUp(isPeriodic bool) {
	reservationMutex.Lock()
	for id, chunks := range reservedChunks {
		now := time.Now().Unix()
		for uuid, reservedChunk := range chunks {
			if reservedChunk.Expiry < now {
				delete(reservedChunks[id], uuid)
			}
		}
	}
	reservationMutex.Unlock()

	if isPeriodic {
		go func() {
			time.Sleep(time.Minute * 5)
			cleanUp(true)
		}()
	}
}
