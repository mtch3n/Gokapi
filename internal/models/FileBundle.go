package models

import (
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
	// so a folder-level share key can be stored the same way once a caller populates it. Not
	// currently written by any upload path (folder access today is derived from member files'
	// PasswordHash, see AccessMode / isValidFolderPassword) - added for schema parity, expected
	// to be populated by a follow-up that adds folder-level generated passwords.
	EncryptedSharePassword []byte `json:"-" redis:"EncryptedSharePassword"`
}

// Populate scans all files and returns those belonging to this bundle
func (b *FileBundle) Populate(files map[string]File) ([]File, int64, int) {
	var memberFiles []File
	var totalSize int64
	count := 0

	for _, file := range files {
		if file.BundleId == b.Id && !file.IsPendingForDeletion() {
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
