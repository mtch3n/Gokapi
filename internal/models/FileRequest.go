package models

import (
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/storage/chunking/chunkreservation"
)

// FileRequest contains information about a file request
type FileRequest struct {
	Id              string   `json:"id" redis:"id"`                     // The internal ID of the file request
	UserId          int      `json:"userid" redis:"userid"`             // The user ID of the owner
	MaxFiles        int      `json:"maxfiles" redis:"maxfiles"`         // The maximum number of files allowed
	MaxSize         int      `json:"maxsize" redis:"maxsize"`           // The maximum file size allowed in MB
	Expiry          int64    `json:"expiry" redis:"expiry"`             // The expiry time of the file request
	CreationDate    int64    `json:"creationdate" redis:"creationdate"` // The timestamp of the file request creation
	Name            string   `json:"name" redis:"-"`                    // The given name for the file request, held in plaintext only in memory. Will be NameUnavailable while the instance is sealed
	ApiKey          string   `json:"apikey" redis:"apikey"`             // The API key related to the file request
	Notes           string   `json:"notes" redis:"-"`                   // The custom note that was set for this file request, held in plaintext only in memory. Empty while the instance is sealed
	Closed          bool     `json:"closed" redis:"closed"`             // True if the request was marked complete and no longer accepts uploads
	UploadedFiles   int      `json:"uploadedfiles" redis:"-"`           // Contains the number of uploaded files for this request. Needs to be calculated with Populate()
	CombinedMaxSize int      `json:"combinedmaxsize" redis:"-"`         // The lesser of MaxSize and the server's max upload size. Needs to be calculated with Populate()
	ReservedUploads int      `json:"reserveduploads" redis:"-"`         // How many uploads are currently reserved but not finalised. Needs to be calculated with Populate()
	LastUpload      int64    `json:"lastupload" redis:"-"`              // Contains the timestamp of the last upload for this request. Needs to be calculated with Populate()
	TotalFileSize   int64    `json:"totalfilesize" redis:"-"`           // Contains the file size of all uploaded files. Needs to be calculated with Populate()
	FileIdList      []string `json:"fileidlist" redis:"-"`              // Contains an array of the IDs of all uploaded files. Needs to be calculated with Populate()
	Files           []File   `json:"-" redis:"-"`                       // Contains an array of the IDs of all uploaded files. Needs to be calculated with Populate()
	// NameEncryptedRaw carries the exact bytes stored for the name, mirroring
	// models.File.NameEncryptedRaw - see that field's comment for why this exists. For Redis this
	// also doubles as the wire field: the "NameEncrypted" tag is what SaveFileRequest writes into
	// the hash.
	NameEncryptedRaw []byte `json:"-" redis:"NameEncrypted"`
	// NoteEncryptedRaw is the same carry-through for Notes. Unlike Name, an empty note is a normal
	// value (see encryptNoteForSave), so this exists purely for the save-back-unchanged path, not
	// for distinguishing "empty" from "sealed".
	NoteEncryptedRaw []byte `json:"-" redis:"NoteEncrypted"`
	// Collaborators are the staff users who may view this request and download the files it
	// collects, and nothing else - every write stays with the owner (UserId). Ids are what is
	// stored; Name is filled by the API layer for display and never persisted. A collaborator is
	// not a share recipient: a recipient is an outside address with no account whose grant opens
	// the public upload page, this is an account that sees the request in its own dashboard.
	Collaborators []FileRequestCollaborator `json:"collaborators" redis:"-"`
	// CollaboratorsRaw is the JSON array of ids exactly as stored, e.g. "[2,5]". It is the wire
	// field for Redis (the struct scanner cannot fill a slice) and what the sqlite/postgres
	// providers write into the Collaborators column. Always kept in step with Collaborators by
	// SetCollaboratorIds; nothing else should assign it.
	CollaboratorsRaw string `json:"-" redis:"Collaborators"`
	// OwnerName is the owner's display name, filled by the API layer so a collaborator's list can
	// say whose request it is. Never persisted.
	OwnerName string `json:"ownername" redis:"-"`
}

// FileRequestCollaborator is one entry of FileRequest.Collaborators.
type FileRequestCollaborator struct {
	Id   int    `json:"id"`
	Name string `json:"name"`
}

// DecodeCollaborators parses the stored JSON array of user ids. An empty string is accepted as
// "nobody": a Redis hash written before the field existed has no value at all. The result is
// sorted, de-duplicated and free of ids that cannot name a user.
func DecodeCollaborators(raw string) ([]int, error) {
	if raw == "" {
		return []int{}, nil
	}
	var ids []int
	if err := json.Unmarshal([]byte(raw), &ids); err != nil {
		return nil, err
	}
	return normaliseCollaboratorIds(ids), nil
}

// EncodeCollaborators is the inverse of DecodeCollaborators. Never returns "" - the stored value
// is always a JSON array, so every reader sees valid JSON.
func EncodeCollaborators(ids []int) string {
	out, err := json.Marshal(normaliseCollaboratorIds(ids))
	if err != nil {
		// A []int cannot fail to marshal; guarding rather than ignoring so a future change to
		// the element type cannot silently store garbage.
		panic(err)
	}
	return string(out)
}

func normaliseCollaboratorIds(ids []int) []int {
	result := make([]int, 0, len(ids))
	seen := make(map[int]bool, len(ids))
	for _, id := range ids {
		if id <= 0 || seen[id] {
			continue
		}
		seen[id] = true
		result = append(result, id)
	}
	slices.Sort(result)
	return result
}

// CollaboratorIds returns the ids in Collaborators, in stored order.
func (f *FileRequest) CollaboratorIds() []int {
	ids := make([]int, 0, len(f.Collaborators))
	for _, c := range f.Collaborators {
		ids = append(ids, c.Id)
	}
	return ids
}

// SetCollaboratorIds replaces the list and keeps CollaboratorsRaw in step. Names are cleared:
// they are display data the API layer fills from the user table on the way out.
func (f *FileRequest) SetCollaboratorIds(ids []int) {
	clean := normaliseCollaboratorIds(ids)
	f.Collaborators = make([]FileRequestCollaborator, 0, len(clean))
	for _, id := range clean {
		f.Collaborators = append(f.Collaborators, FileRequestCollaborator{Id: id})
	}
	f.CollaboratorsRaw = EncodeCollaborators(clean)
}

// IsCollaborator reports whether userId is in Collaborators. The owner is never a collaborator;
// callers test UserId separately.
func (f *FileRequest) IsCollaborator(userId int) bool {
	for _, c := range f.Collaborators {
		if c.Id == userId {
			return true
		}
	}
	return false
}

// Populate inserts the number of uploaded files and the last upload date
func (f *FileRequest) Populate(files map[string]File, maxServerSize int) {
	f.FileIdList = make([]string, 0)
	f.Files = make([]File, 0)
	for _, file := range files {
		if file.UploadRequestId == f.Id && !file.IsPendingForDeletion() {
			f.TotalFileSize = f.TotalFileSize + file.SizeBytes
			f.FileIdList = append(f.FileIdList, file.Id)
			f.Files = append(f.Files, file)
			if file.UploadDate > f.LastUpload {
				f.LastUpload = file.UploadDate
			}
		}
	}
	f.CombinedMaxSize = f.MaxSize
	if f.MaxSize == 0 || f.MaxSize > maxServerSize {
		f.CombinedMaxSize = maxServerSize
	}
	f.UploadedFiles = len(f.FileIdList)
	f.ReservedUploads = chunkreservation.GetCount(f.Id)
}

// GetReadableDateLastUpdate returns the last update date as YYYY-MM-DD HH:MM:SS
func (f *FileRequest) GetReadableDateLastUpdate() string {
	if f.LastUpload == 0 {
		return "None"
	}
	return time.Unix(f.LastUpload, 0).Format("2006-01-02 15:04:05")
}

// GetReadableTotalSize returns the total file size in a human-readable format
func (f *FileRequest) GetReadableTotalSize() string {
	return helper.ByteCountSI(f.TotalFileSize)
}

// GetFilesAsString returns a comma-separated list of file IDs
func (f *FileRequest) GetFilesAsString() string {
	return strings.Join(f.FileIdList, ",")
}

// IsUnlimitedSize returns true if there is no size limit
func (f *FileRequest) IsUnlimitedSize() bool {
	return f.MaxSize == 0
}

// IsUnlimitedFiles returns true if there is no file limit
func (f *FileRequest) IsUnlimitedFiles() bool {
	return f.MaxFiles == 0
}

// IsUnlimitedTime returns true if there is no expiry time
func (f *FileRequest) IsUnlimitedTime() bool {
	return f.Expiry == 0
}

// IsExpired returns true if the file request has expired
func (f *FileRequest) IsExpired() bool {
	return !f.IsUnlimitedTime() && time.Now().Unix() > f.Expiry
}

// DisplayName returns Name, or NameUnavailable if the name could not be decrypted (see
// models.NameUnavailable). Mirrors models.FileBundle.DisplayName - see that comment for why Name
// itself is left untouched. Notes has no equivalent: an empty note is a normal value, not a sign
// of a sealed instance (see the Note handling in the sqlite/postgres/redis providers), so it is
// rendered as-is everywhere.
func (f *FileRequest) DisplayName() string {
	if f.Name == "" {
		return NameUnavailable
	}
	return f.Name
}

// HasRestrictions returns true if the file request has any restrictions e.g. size or time limit
func (f *FileRequest) HasRestrictions() bool {
	return !(f.IsUnlimitedSize() && f.IsUnlimitedFiles() && f.IsUnlimitedTime())
}

// FilesRemaining returns the number of files that can still be uploaded
func (f *FileRequest) FilesRemaining() int {
	result := f.MaxFiles - f.UploadedFiles - f.ReservedUploads
	if result < 0 {
		return 0
	}
	return result
}
