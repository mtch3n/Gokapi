package models

import (
	"sort"
	"time"
)

// FileBundleGracePeriod is the time window after creation within which a bundle is kept
// even if it has no valid members (24 hours)
const FileBundleGracePeriod = 24 * 60 * 60

// FileBundle contains information about a file bundle (folder)
type FileBundle struct {
	Id     string `json:"id" redis:"id"`         // The internal ID of the bundle
	Name   string `json:"name" redis:"-"`        // The name of the bundle, held in plaintext only in memory. Will be NameUnavailable while the instance is sealed
	UserId int    `json:"userid" redis:"userid"` // The user ID of the owner
	// NameEncryptedRaw carries the exact bytes stored for the name (format-prefixed ciphertext or
	// plaintext, see encryption.EncryptFileName/DecryptFileName), alongside the decrypted Name
	// above. Mirrors models.File.NameEncryptedRaw - see that field's comment for why this exists:
	// it is what lets a caller save this FileBundle back unchanged (most importantly
	// database.Migrate, which runs before the master key is loaded) without losing an encrypted
	// name it can never decrypt. For Redis this also doubles as the wire field: the
	// "NameEncrypted" tag is what SaveFileBundle writes into the hash.
	NameEncryptedRaw []byte `json:"-" redis:"NameEncrypted"`
	CreationDate     int64  `json:"creationdate" redis:"creationdate"` // The timestamp of the bundle creation
	// EncryptedSharePassword mirrors models.File.EncryptedSharePassword for bundles (folders),
	// so a folder-level share key can be stored the same way a member's is - see
	// storage.EncryptSharePassword and the apiFolderCreate/storeBundleShareKey callers that
	// populate it.
	EncryptedSharePassword []byte `json:"-" redis:"EncryptedSharePassword"`
	// PasswordHash is the hash of the folder's OWN password, mirroring models.File.PasswordHash.
	// This - not any member's PasswordHash - is what gates the folder: a bundle is the unit of
	// sharing, so its access settings live here instead of being inferred from members (which
	// made a folder's password only as strong as an "every protected member must match" scan,
	// and one per-file edit away from becoming permanently unopenable - see the design doc this
	// column implements). Hidden from JSON, unlike File.PasswordHash: apiFolderList marshals
	// models.FileBundle directly with no FileApiOutput-style redaction step to catch it.
	PasswordHash string `json:"-" redis:"PasswordHash"`
	// ExpireAt is the UTC timestamp the folder itself expires. A member's own ExpireAt becomes
	// inert once it belongs to a bundle - see models.File.IsBundleMember and IsExpired below.
	ExpireAt int64 `json:"expireat" redis:"ExpireAt"`
	// UnlimitedTime is true if the folder has no expiry.
	UnlimitedTime bool `json:"unlimitedtime" redis:"UnlimitedTime"`
	// DownloadsRemaining is the folder's own download allowance. One visit - the whole zip, or
	// any single member - spends one, regardless of how many files that visit actually touches;
	// see the atomic decrement in the database provider (DecreaseBundleDownloadsRemaining) and
	// its caller in webserver.pubApiFolderZip. A member's own DownloadsRemaining becomes inert
	// once it belongs to a bundle, the same as ExpireAt above.
	DownloadsRemaining int `json:"downloadsremaining" redis:"DownloadsRemaining"`
	// UnlimitedDownloads is true if the folder has no download limit.
	UnlimitedDownloads bool `json:"unlimiteddownloads" redis:"UnlimitedDownloads"`
}

// IsExpired reports whether the folder's own expiry has passed. Mirrors storage.IsExpiredFile's
// expiry half, but only that half: a memberless bundle is handled by its caller (see
// webserver.bundleAvailability), not by this method.
func (b *FileBundle) IsExpired(timeNow int64) bool {
	return b.ExpireAt < timeNow && !b.UnlimitedTime
}

// IsAvailable reports whether the folder itself may currently be opened at all: not expired, and
// its own download allowance is not exhausted. It says nothing about membership - a bundle with
// zero members is still "available" by this method alone; callers combine this with their own
// membership check (see webserver.bundleAvailability) because what counts as a member differs by
// caller (see models.File.IsBundleMember).
func (b *FileBundle) IsAvailable(timeNow int64) bool {
	if b.IsExpired(timeNow) {
		return false
	}
	if !b.UnlimitedDownloads && b.DownloadsRemaining < 1 {
		return false
	}
	return true
}

// DeriveBundleSettingsFromMembers computes the password, expiry and download allowance a bundle
// should be backfilled with from its current members (see File.IsBundleMember), for the
// migration that moves these settings off members and onto the bundle itself.
//
// Members can already disagree - a raw API edit could touch one member without the others, and
// there is no single right merge for a genuine disagreement. This picks the MOST RESTRICTIVE
// value along each axis rather than an arbitrary member's, so the migration can only leave a
// bundle as-or-less accessible than it was, never more:
//   - password: the earliest-uploaded member (by UploadDate, tied on Id for determinism) that
//     actually has one. A bundle stays protected if any member ever was - unprotected would be
//     strictly more accessible than the all-members-must-match gate the bundle replaces.
//   - expiry: the smallest ExpireAt among members with a real one; UnlimitedTime only if every
//     member was unlimited. A folder cannot outlive the earliest of its members' own expiries.
//   - downloads: the smallest DownloadsRemaining among members with a real cap;
//     UnlimitedDownloads only if every member was unlimited. Same reasoning as expiry.
//
// Members that all agree collapse to the shared value on each axis, so this is also correct -
// and not merely safe - for the common case. A bundle with no members keeps every field at its
// zero value, which is already the least accessible state (immediately expired, no downloads
// left) - moot in practice, since a memberless bundle is refused outright before any of these
// fields is consulted (see webserver.bundleAvailability).
func DeriveBundleSettingsFromMembers(members []File) (passwordHash string, expireAt int64, unlimitedTime bool, downloadsRemaining int, unlimitedDownloads bool) {
	if len(members) == 0 {
		return "", 0, false, 0, false
	}
	sorted := make([]File, len(members))
	copy(sorted, members)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].UploadDate != sorted[j].UploadDate {
			return sorted[i].UploadDate < sorted[j].UploadDate
		}
		return sorted[i].Id < sorted[j].Id
	})

	for _, member := range sorted {
		if member.PasswordHash != "" {
			passwordHash = member.PasswordHash
			break
		}
	}

	unlimitedTime = true
	for _, member := range sorted {
		if member.UnlimitedTime {
			continue
		}
		unlimitedTime = false
		if expireAt == 0 || member.ExpireAt < expireAt {
			expireAt = member.ExpireAt
		}
	}

	unlimitedDownloads = true
	haveCappedMember := false
	for _, member := range sorted {
		if member.UnlimitedDownloads {
			continue
		}
		unlimitedDownloads = false
		if !haveCappedMember || member.DownloadsRemaining < downloadsRemaining {
			downloadsRemaining = member.DownloadsRemaining
			haveCappedMember = true
		}
	}

	return passwordHash, expireAt, unlimitedTime, downloadsRemaining, unlimitedDownloads
}

// Populate scans all files and returns those belonging to this bundle. The count and total size
// it returns count only current members (see File.IsBundleMember) - a disposed member's bytes are
// no longer stored, so counting it here would tell the owner the folder holds more than a
// recipient can actually receive.
func (b *FileBundle) Populate(files map[string]File) ([]File, int64, int) {
	var memberFiles []File
	var totalSize int64
	count := 0

	for _, file := range files {
		if file.IsBundleMember(b.Id) {
			memberFiles = append(memberFiles, file)
			totalSize += file.SizeBytes
			count++
		}
	}

	return memberFiles, totalSize, count
}

// IsOlderThanGracePeriod returns true if the bundle was created more than 24 hours ago
func (b *FileBundle) IsOlderThanGracePeriod() bool {
	return time.Now().Unix() > b.CreationDate+FileBundleGracePeriod
}

// DisplayName returns Name, or NameUnavailable if the name could not be decrypted (see
// models.NameUnavailable). A real bundle can never legitimately have an empty name - Create
// always sets one - so an empty Name here means this row could not be decrypted, typically
// because the instance is still sealed. Callers rendering a bundle to JSON or mail should use
// this instead of Name directly; Name itself is left untouched so a caller that saves this
// FileBundle back unchanged (see NameEncryptedRaw) does not have the placeholder mistaken for a
// real name.
func (b *FileBundle) DisplayName() string {
	if b.Name == "" {
		return NameUnavailable
	}
	return b.Name
}
