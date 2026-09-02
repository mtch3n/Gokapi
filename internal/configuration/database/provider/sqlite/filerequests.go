package sqlite

import (
	"database/sql"
	"errors"

	"github.com/forceu/gokapi/internal/encryption"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
)

// fileRequestColumns is listed explicitly rather than using SELECT *, for the same reason
// metadata.go's metaDataColumns and filebundles.go's fileBundleColumns are: the scans below are
// positional, and an upgraded database orders its columns differently from a fresh one.
const fileRequestColumns = "Id, NameEncrypted, UserId, Expiry, MaxFiles, MaxSize, Creation, ApiKey, NoteEncrypted, Closed, Collaborators, ClosedAt"

type schemaFileRequests struct {
	Id            string
	NameEncrypted []byte
	UserId        int
	Expiry        int64
	MaxFiles      int
	MaxSize       int
	Creation      int64
	ApiKey        string
	NoteEncrypted []byte
	Closed        int
	Collaborators string
	ClosedAt      int64
}

func (rowData schemaFileRequests) toFileRequestModel() models.FileRequest {
	result := models.FileRequest{
		Id:               rowData.Id,
		Name:             encryption.DecryptFileName(rowData.NameEncrypted),
		NameEncryptedRaw: rowData.NameEncrypted,
		UserId:           rowData.UserId,
		MaxFiles:         rowData.MaxFiles,
		MaxSize:          rowData.MaxSize,
		Expiry:           rowData.Expiry,
		CreationDate:     rowData.Creation,
		ApiKey:           rowData.ApiKey,
		Notes:            encryption.DecryptFileName(rowData.NoteEncrypted),
		NoteEncryptedRaw: rowData.NoteEncrypted,
		Closed:           rowData.Closed == 1,
		ClosedAt:         rowData.ClosedAt,
	}
	ids, err := models.DecodeCollaborators(rowData.Collaborators)
	helper.Check(err)
	result.SetCollaboratorIds(ids)
	return result
}

// GetFileRequest returns the FileRequest or false if not found
func (p DatabaseProvider) GetFileRequest(id string) (models.FileRequest, bool) {
	if id == "" {
		return models.FileRequest{}, false
	}
	var rowResult schemaFileRequests
	row := p.sqliteDb.QueryRow("SELECT "+fileRequestColumns+" FROM UploadRequests WHERE Id = ?", id)
	err := row.Scan(&rowResult.Id, &rowResult.NameEncrypted, &rowResult.UserId, &rowResult.Expiry,
		&rowResult.MaxFiles, &rowResult.MaxSize, &rowResult.Creation, &rowResult.ApiKey, &rowResult.NoteEncrypted,
		&rowResult.Closed, &rowResult.Collaborators, &rowResult.ClosedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.FileRequest{}, false
		}
		helper.Check(err)
		return models.FileRequest{}, false
	}
	return rowResult.toFileRequestModel(), true
}

// GetAllFileRequests returns an array with all file requests, ordered by creation date
func (p DatabaseProvider) GetAllFileRequests() []models.FileRequest {
	result := make([]models.FileRequest, 0)
	// Tie-broken on Id rather than Name: Name is now ciphertext, and ordering by it would be
	// meaningless.
	rows, err := p.sqliteDb.Query("SELECT " + fileRequestColumns + " FROM UploadRequests ORDER BY Creation DESC, Id")
	helper.Check(err)
	defer rows.Close()
	for rows.Next() {
		rowData := schemaFileRequests{}
		err = rows.Scan(&rowData.Id, &rowData.NameEncrypted, &rowData.UserId, &rowData.Expiry, &rowData.MaxFiles,
			&rowData.MaxSize, &rowData.Creation, &rowData.ApiKey, &rowData.NoteEncrypted, &rowData.Closed,
			&rowData.Collaborators, &rowData.ClosedAt)
		helper.Check(err)
		result = append(result, rowData.toFileRequestModel())
	}
	return result
}

// SaveFileRequest stores the file request associated with the file in the database
func (p DatabaseProvider) SaveFileRequest(request models.FileRequest) {
	closed := 0
	if request.Closed {
		closed = 1
	}
	encryptedName, err := p.encryptRequestNameForSave(request)
	helper.Check(err)
	encryptedNote, err := p.encryptNoteForSave(request)
	helper.Check(err)
	newData := schemaFileRequests{
		Id:            request.Id,
		NameEncrypted: encryptedName,
		UserId:        request.UserId,
		MaxFiles:      request.MaxFiles,
		MaxSize:       request.MaxSize,
		Expiry:        request.Expiry,
		Creation:      request.CreationDate,
		ApiKey:        request.ApiKey,
		NoteEncrypted: encryptedNote,
		Closed:        closed,
		Collaborators: models.EncodeCollaborators(request.CollaboratorIds()),
		ClosedAt:      request.ClosedAt,
	}

	_, err = p.sqliteDb.Exec(`INSERT OR REPLACE INTO UploadRequests
   				 (id, NameEncrypted, userid, expiry, maxFiles, maxSize, creation, apiKey, NoteEncrypted, closed, Collaborators, ClosedAt)
         			 VALUES  (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		newData.Id, newData.NameEncrypted, newData.UserId, newData.Expiry, newData.MaxFiles, newData.MaxSize,
		newData.Creation, newData.ApiKey, newData.NoteEncrypted, newData.Closed, newData.Collaborators, newData.ClosedAt)
	helper.Check(err)
}

// encryptRequestNameForSave returns the value to store in NameEncrypted for this request. Mirrors
// metadata.go's encryptNameForSave exactly - see that comment for the full reasoning. An empty
// name is never a real one - filerequest.New always sets one - so it means this models.FileRequest
// was read back while the instance was still sealed.
func (p DatabaseProvider) encryptRequestNameForSave(request models.FileRequest) ([]byte, error) {
	if request.Name != "" {
		return encryption.EncryptFileName(request.Name)
	}
	if request.NameEncryptedRaw != nil {
		return request.NameEncryptedRaw, nil
	}
	var storedName []byte
	row := p.sqliteDb.QueryRow("SELECT NameEncrypted FROM UploadRequests WHERE id = ?", request.Id)
	err := row.Scan(&storedName)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return storedName, err
}

// encryptNoteForSave returns the value to store in NoteEncrypted for this request. Deliberately
// does NOT use the "empty means sealed" heuristic encryptRequestNameForSave relies on: an empty
// note is a normal value - the owner may clear a note they previously set - and treating that the
// same as "read while sealed" would silently restore a note the owner just cleared. Checked
// explicitly against encryption.IsSealed instead: while unsealed, Notes is always encrypted as
// given, empty or not; while sealed, the exact stored bytes are written back verbatim (via
// NoteEncryptedRaw, or a lookup as a fallback) so a bookkeeping write allowed while sealed does not
// lose the note.
func (p DatabaseProvider) encryptNoteForSave(request models.FileRequest) ([]byte, error) {
	if !encryption.IsSealed() {
		return encryption.EncryptFileName(request.Notes)
	}
	if request.NoteEncryptedRaw != nil {
		return request.NoteEncryptedRaw, nil
	}
	var storedNote []byte
	row := p.sqliteDb.QueryRow("SELECT NoteEncrypted FROM UploadRequests WHERE id = ?", request.Id)
	err := row.Scan(&storedNote)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return storedNote, err
}

// DeleteFileRequest deletes a file request with the given ID
func (p DatabaseProvider) DeleteFileRequest(request models.FileRequest) {
	if request.Id == "" {
		return
	}
	_, err := p.sqliteDb.Exec("DELETE FROM UploadRequests WHERE Id = ?", request.Id)
	helper.Check(err)
}

// migrateFileRequestNamesAndNotes re-encrypts every request name and note still stored in their
// pre-v23 plaintext columns and then drops those columns, reporting how many values it converted
// in total. Same shape as metadata.go's MigratePlaintextFileNames - see that comment for why this
// cannot run from Upgrade, and why re-running it is a safe no-op. Name and note are migrated
// together in one pass since they live on the same row, but each column is guarded and dropped
// independently, so a partially-upgraded table (e.g. one column already migrated by an earlier,
// interrupted run) is still handled correctly.
func (p DatabaseProvider) migrateFileRequestNamesAndNotes() int {
	migrated := 0
	if p.columnExists("UploadRequests", "name") {
		rows, err := p.sqliteDb.Query(`SELECT id, name FROM UploadRequests WHERE NameEncrypted IS NULL`)
		helper.Check(err)
		plaintextNames := make(map[string]string)
		for rows.Next() {
			var id, name string
			err = rows.Scan(&id, &name)
			helper.Check(err)
			plaintextNames[id] = name
		}
		helper.Check(rows.Err())
		rows.Close()

		for id, name := range plaintextNames {
			var encryptedName []byte
			encryptedName, err = encryption.EncryptFileName(name)
			helper.Check(err)
			_, err = p.sqliteDb.Exec(`UPDATE UploadRequests SET NameEncrypted = ? WHERE id = ?`, encryptedName, id)
			helper.Check(err)
		}

		err = p.rawSqlite(`ALTER TABLE UploadRequests DROP COLUMN "name"`)
		helper.Check(err)
		migrated += len(plaintextNames)
	}

	if p.columnExists("UploadRequests", "note") {
		rows, err := p.sqliteDb.Query(`SELECT id, note FROM UploadRequests WHERE NoteEncrypted IS NULL`)
		helper.Check(err)
		plaintextNotes := make(map[string]string)
		for rows.Next() {
			var id, note string
			err = rows.Scan(&id, &note)
			helper.Check(err)
			plaintextNotes[id] = note
		}
		helper.Check(rows.Err())
		rows.Close()

		for id, note := range plaintextNotes {
			var encryptedNote []byte
			encryptedNote, err = encryption.EncryptFileName(note)
			helper.Check(err)
			_, err = p.sqliteDb.Exec(`UPDATE UploadRequests SET NoteEncrypted = ? WHERE id = ?`, encryptedNote, id)
			helper.Check(err)
		}

		err = p.rawSqlite(`ALTER TABLE UploadRequests DROP COLUMN "note"`)
		helper.Check(err)
		migrated += len(plaintextNotes)
	}

	return migrated
}
