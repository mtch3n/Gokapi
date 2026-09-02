package redis

import (
	"cmp"
	"slices"

	"github.com/forceu/gokapi/internal/encryption"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
	redigo "github.com/gomodule/redigo/redis"
)

const (
	prefixFileRequests = "frq:"
)

func dbToFileRequest(input []any) (models.FileRequest, error) {
	var result models.FileRequest
	err := redigo.ScanStruct(input, &result)
	if err != nil {
		return models.FileRequest{}, err
	}
	// NameEncryptedRaw/NoteEncryptedRaw are deliberately left populated here (not nilled out after
	// decrypting into Name/Notes) so a caller that re-saves this FileRequest unchanged can write
	// the original bytes back verbatim rather than re-deriving them - see
	// encryptRequestNameForSave/encryptNoteForSave and models.FileRequest.NameEncryptedRaw.
	result.Name = encryption.DecryptFileName(result.NameEncryptedRaw)
	result.Notes = encryption.DecryptFileName(result.NoteEncryptedRaw)
	ids, err := models.DecodeCollaborators(result.CollaboratorsRaw)
	if err != nil {
		return models.FileRequest{}, err
	}
	result.SetCollaboratorIds(ids)
	return result, nil
}

// GetFileRequest returns the FileRequest or false if not found
func (p DatabaseProvider) GetFileRequest(id string) (models.FileRequest, bool) {
	if id == "" {
		return models.FileRequest{}, false
	}
	result, ok := p.getHashMap(prefixFileRequests + id)
	if !ok {
		return models.FileRequest{}, false
	}
	request, err := dbToFileRequest(result)
	helper.Check(err)
	return request, true
}

// GetAllFileRequests returns an array with all file requests, ordered by creation date
func (p DatabaseProvider) GetAllFileRequests() []models.FileRequest {
	var result []models.FileRequest
	maps := p.getAllHashesWithPrefix(prefixFileRequests)
	for _, v := range maps {
		request, err := dbToFileRequest(v)
		helper.Check(err)
		result = append(result, request)
	}
	return sortFilerequests(result)
}

func sortFilerequests(users []models.FileRequest) []models.FileRequest {
	// Tie-broken on Id rather than Name: Name is now ciphertext, and ordering by it would be
	// meaningless.
	slices.SortFunc(users, func(a, b models.FileRequest) int {
		return cmp.Or(
			cmp.Compare(b.CreationDate, a.CreationDate),
			cmp.Compare(a.Id, b.Id),
		)
	})
	return users
}

// SaveFileRequest stores the file request associated with the file in the database
func (p DatabaseProvider) SaveFileRequest(request models.FileRequest) {
	encryptedName, err := p.encryptRequestNameForSave(request)
	helper.Check(err)
	encryptedNote, err := p.encryptNoteForSave(request)
	helper.Check(err)
	request.NameEncryptedRaw = encryptedName
	request.NoteEncryptedRaw = encryptedNote
	// The struct flattener cannot write a slice, so the JSON text is what goes into the hash
	// (see models.FileRequest.CollaboratorsRaw). Re-encoded from the ids rather than trusted, so
	// a caller that edited Collaborators without SetCollaboratorIds still stores the right list.
	request.CollaboratorsRaw = models.EncodeCollaborators(request.CollaboratorIds())
	p.setHashMap(p.buildArgs(prefixFileRequests + request.Id).AddFlat(request))
}

// encryptRequestNameForSave returns the value to store in the NameEncrypted hash field for this
// request. Mirrors metadata.go's encryptNameForSave exactly - see that comment for the full
// reasoning. An empty name is never a real one - filerequest.New always sets one - so it means
// this models.FileRequest was read back while the instance was still sealed.
func (p DatabaseProvider) encryptRequestNameForSave(request models.FileRequest) ([]byte, error) {
	if request.Name != "" {
		return encryption.EncryptFileName(request.Name)
	}
	if request.NameEncryptedRaw != nil {
		return request.NameEncryptedRaw, nil
	}
	hash, ok := p.getHashMap(prefixFileRequests + request.Id)
	if !ok {
		return nil, nil
	}
	storedName, ok := hashFieldString(hash, "NameEncrypted")
	if !ok {
		return nil, nil
	}
	return []byte(storedName), nil
}

// encryptNoteForSave returns the value to store in the NoteEncrypted hash field for this request.
// Deliberately does NOT use the "empty means sealed" heuristic encryptRequestNameForSave relies
// on: an empty note is a normal value - the owner may clear a note they previously set - and
// treating that the same as "read while sealed" would silently restore a note the owner just
// cleared. Checked explicitly against encryption.IsSealed instead: while unsealed, Notes is always
// encrypted as given, empty or not; while sealed, the exact stored bytes are written back verbatim.
func (p DatabaseProvider) encryptNoteForSave(request models.FileRequest) ([]byte, error) {
	if !encryption.IsSealed() {
		return encryption.EncryptFileName(request.Notes)
	}
	if request.NoteEncryptedRaw != nil {
		return request.NoteEncryptedRaw, nil
	}
	hash, ok := p.getHashMap(prefixFileRequests + request.Id)
	if !ok {
		return nil, nil
	}
	storedNote, ok := hashFieldString(hash, "NoteEncrypted")
	if !ok {
		return nil, nil
	}
	return []byte(storedNote), nil
}

// DeleteFileRequest deletes a file request with the given ID
func (p DatabaseProvider) DeleteFileRequest(request models.FileRequest) {
	p.deleteKey(prefixFileRequests + request.Id)
}

// migrateFileRequestNamesAndNotes re-encrypts every request name and note still stored in their
// plaintext hash fields and then removes those fields, reporting how many values it converted in
// total. Same shape as metadata.go's migrateFileMetaDataNames. Name and note are migrated
// independently within the same pass over each hash, since a hash written before this feature
// existed carries both plaintext fields together.
func (p DatabaseProvider) migrateFileRequestNamesAndNotes() int {
	migrated := 0
	for key, hash := range p.getAllHashesWithPrefix(prefixFileRequests) {
		if plaintextName, ok := hashFieldString(hash, "name"); ok {
			encryptedName, err := encryption.EncryptFileName(plaintextName)
			helper.Check(err)
			p.setHashMap(p.buildArgs(key).Add("NameEncrypted").Add(encryptedName))
			p.deleteHashField(key, "name")
			migrated++
		}
		if plaintextNote, ok := hashFieldString(hash, "notes"); ok {
			encryptedNote, err := encryption.EncryptFileName(plaintextNote)
			helper.Check(err)
			p.setHashMap(p.buildArgs(key).Add("NoteEncrypted").Add(encryptedNote))
			p.deleteHashField(key, "notes")
			migrated++
		}
	}
	return migrated
}
