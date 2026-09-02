package postgres

import (
	"database/sql"
	"errors"

	"github.com/forceu/gokapi/internal/encryption"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
)

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
	Closed        bool
	Collaborators string
	ClosedAt      int64
}

func (s schemaFileRequests) toFileRequest() models.FileRequest {
	result := models.FileRequest{
		Id:               s.Id,
		Name:             encryption.DecryptFileName(s.NameEncrypted),
		NameEncryptedRaw: s.NameEncrypted,
		UserId:           s.UserId,
		MaxFiles:         s.MaxFiles,
		MaxSize:          s.MaxSize,
		Expiry:           s.Expiry,
		CreationDate:     s.Creation,
		ApiKey:           s.ApiKey,
		Notes:            encryption.DecryptFileName(s.NoteEncrypted),
		NoteEncryptedRaw: s.NoteEncrypted,
		Closed:           s.Closed,
		ClosedAt:         s.ClosedAt,
	}
	ids, err := models.DecodeCollaborators(s.Collaborators)
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
	row := p.queryRow("SELECT "+fileRequestColumns+" FROM UploadRequests WHERE Id = $1", id)
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
	return rowResult.toFileRequest(), true
}

// GetAllFileRequests returns an array with all file requests, ordered by creation date
func (p DatabaseProvider) GetAllFileRequests() []models.FileRequest {
	result := make([]models.FileRequest, 0)
	// Tie-broken on Id rather than Name: Name is now ciphertext, and ordering by it would be
	// meaningless.
	rows, err := p.query("SELECT " + fileRequestColumns + " FROM UploadRequests ORDER BY Creation DESC, Id")
	helper.Check(err)
	defer rows.Close()
	for rows.Next() {
		rowData := schemaFileRequests{}
		err = rows.Scan(&rowData.Id, &rowData.NameEncrypted, &rowData.UserId, &rowData.Expiry, &rowData.MaxFiles,
			&rowData.MaxSize, &rowData.Creation, &rowData.ApiKey, &rowData.NoteEncrypted, &rowData.Closed,
			&rowData.Collaborators, &rowData.ClosedAt)
		helper.Check(err)
		result = append(result, rowData.toFileRequest())
	}
	helper.Check(rows.Err())
	return result
}

// SaveFileRequest stores the file request associated with the file in the database
func (p DatabaseProvider) SaveFileRequest(request models.FileRequest) {
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
		Closed:        request.Closed,
		Collaborators: models.EncodeCollaborators(request.CollaboratorIds()),
		ClosedAt:      request.ClosedAt,
	}

	_, err = p.exec(`INSERT INTO UploadRequests
					(Id, NameEncrypted, UserId, Expiry, MaxFiles, MaxSize, Creation, ApiKey, NoteEncrypted, Closed, Collaborators, ClosedAt)
					VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12)
					ON CONFLICT (Id) DO UPDATE SET NameEncrypted = EXCLUDED.NameEncrypted, UserId = EXCLUDED.UserId,
						Expiry = EXCLUDED.Expiry, MaxFiles = EXCLUDED.MaxFiles, MaxSize = EXCLUDED.MaxSize,
						Creation = EXCLUDED.Creation, ApiKey = EXCLUDED.ApiKey, NoteEncrypted = EXCLUDED.NoteEncrypted,
						Closed = EXCLUDED.Closed, Collaborators = EXCLUDED.Collaborators, ClosedAt = EXCLUDED.ClosedAt`,
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
	row := p.queryRow("SELECT NameEncrypted FROM UploadRequests WHERE Id = $1", request.Id)
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
// given, empty or not; while sealed, the exact stored bytes are written back verbatim.
func (p DatabaseProvider) encryptNoteForSave(request models.FileRequest) ([]byte, error) {
	if !encryption.IsSealed() {
		return encryption.EncryptFileName(request.Notes)
	}
	if request.NoteEncryptedRaw != nil {
		return request.NoteEncryptedRaw, nil
	}
	var storedNote []byte
	row := p.queryRow("SELECT NoteEncrypted FROM UploadRequests WHERE Id = $1", request.Id)
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
	_, err := p.exec("DELETE FROM UploadRequests WHERE Id = $1", request.Id)
	helper.Check(err)
}

// migrateFileRequestNamesAndNotes re-encrypts every request name and note still stored in their
// pre-v23 plaintext columns and then drops those columns, reporting how many values it converted
// in total. Same shape as metadata.go's MigratePlaintextFileNames. Name and note are migrated
// independently - each column is guarded and dropped on its own - so a partially-upgraded table is
// still handled correctly.
func (p DatabaseProvider) migrateFileRequestNamesAndNotes() int {
	migrated := 0

	var nameColumnExists bool
	row := p.queryRow(`SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_name = 'uploadrequests' AND column_name = 'name')`)
	err := row.Scan(&nameColumnExists)
	helper.Check(err)
	if nameColumnExists {
		rows, queryErr := p.query(`SELECT Id, Name FROM UploadRequests WHERE NameEncrypted IS NULL`)
		helper.Check(queryErr)
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
			_, err = p.exec(`UPDATE UploadRequests SET NameEncrypted = $1 WHERE Id = $2`, encryptedName, id)
			helper.Check(err)
		}

		_, err = p.exec(`ALTER TABLE UploadRequests DROP COLUMN Name`)
		helper.Check(err)
		migrated += len(plaintextNames)
	}

	var noteColumnExists bool
	row = p.queryRow(`SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_name = 'uploadrequests' AND column_name = 'note')`)
	err = row.Scan(&noteColumnExists)
	helper.Check(err)
	if noteColumnExists {
		rows, queryErr := p.query(`SELECT Id, Note FROM UploadRequests WHERE NoteEncrypted IS NULL`)
		helper.Check(queryErr)
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
			_, err = p.exec(`UPDATE UploadRequests SET NoteEncrypted = $1 WHERE Id = $2`, encryptedNote, id)
			helper.Check(err)
		}

		_, err = p.exec(`ALTER TABLE UploadRequests DROP COLUMN Note`)
		helper.Check(err)
		migrated += len(plaintextNotes)
	}

	return migrated
}
