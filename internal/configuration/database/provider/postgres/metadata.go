package postgres

import (
	"bytes"
	"database/sql"
	"encoding/gob"
	"errors"

	"github.com/forceu/gokapi/internal/encryption"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
)

const metaDataColumns = `Id, NameEncrypted, Size, SHA1, ExpireAt, SizeBytes, DownloadsRemaining, DownloadCount,
	PasswordHash, HotlinkId, ContentType, AwsBucket, Encryption, UnlimitedDownloads, UnlimitedTime,
	UserId, UploadDate, PendingDeletion, UploadRequestId, BundleId, EncryptedSharePassword,
	DisposedAt, DisposalReason, WindowOpenedAt`

type schemaMetaData struct {
	Id                     string
	NameEncrypted          []byte
	Size                   string
	SHA1                   string
	ExpireAt               int64
	SizeBytes              int64
	DownloadsRemaining     int
	DownloadCount          int
	PasswordHash           string
	HotlinkId              string
	ContentType            string
	AwsBucket              string
	Encryption             []byte
	UnlimitedDownloads     int
	UnlimitedTime          int
	UserId                 int
	UploadDate             int64
	PendingDeletion        int64
	UploadRequestId        string
	BundleId               string
	EncryptedSharePassword []byte
	DisposedAt             int64
	DisposalReason         int
	WindowOpenedAt         int64
}

func (rowData schemaMetaData) ToFileModel() (models.File, error) {
	result := models.File{
		Id:                     rowData.Id,
		Name:                   encryption.DecryptFileName(rowData.NameEncrypted),
		NameEncryptedRaw:       rowData.NameEncrypted,
		Size:                   rowData.Size,
		SHA1:                   rowData.SHA1,
		ExpireAt:               rowData.ExpireAt,
		SizeBytes:              rowData.SizeBytes,
		DownloadsRemaining:     rowData.DownloadsRemaining,
		DownloadCount:          rowData.DownloadCount,
		PasswordHash:           rowData.PasswordHash,
		HotlinkId:              rowData.HotlinkId,
		ContentType:            rowData.ContentType,
		AwsBucket:              rowData.AwsBucket,
		Encryption:             models.EncryptionInfo{},
		UnlimitedDownloads:     rowData.UnlimitedDownloads == 1,
		UnlimitedTime:          rowData.UnlimitedTime == 1,
		UserId:                 rowData.UserId,
		UploadDate:             rowData.UploadDate,
		PendingDeletion:        rowData.PendingDeletion,
		UploadRequestId:        rowData.UploadRequestId,
		BundleId:               rowData.BundleId,
		EncryptedSharePassword: rowData.EncryptedSharePassword,
		DisposedAt:             rowData.DisposedAt,
		DisposalReason:         rowData.DisposalReason,
		WindowOpenedAt:         rowData.WindowOpenedAt,
	}

	buf := bytes.NewBuffer(rowData.Encryption)
	dec := gob.NewDecoder(buf)
	err := dec.Decode(&result.Encryption)
	return result, err
}

func scanMetaData(scan func(dest ...any) error, rowData *schemaMetaData) error {
	return scan(&rowData.Id, &rowData.NameEncrypted, &rowData.Size, &rowData.SHA1, &rowData.ExpireAt, &rowData.SizeBytes,
		&rowData.DownloadsRemaining, &rowData.DownloadCount, &rowData.PasswordHash, &rowData.HotlinkId,
		&rowData.ContentType, &rowData.AwsBucket, &rowData.Encryption, &rowData.UnlimitedDownloads,
		&rowData.UnlimitedTime, &rowData.UserId, &rowData.UploadDate, &rowData.PendingDeletion,
		&rowData.UploadRequestId, &rowData.BundleId, &rowData.EncryptedSharePassword,
		&rowData.DisposedAt, &rowData.DisposalReason, &rowData.WindowOpenedAt)
}

// GetAllMetadata returns a map of all available files
func (p DatabaseProvider) GetAllMetadata() map[string]models.File {
	result := make(map[string]models.File)
	rows, err := p.query("SELECT " + metaDataColumns + " FROM FileMetaData")
	helper.Check(err)
	defer rows.Close()
	for rows.Next() {
		rowData := schemaMetaData{}
		err = scanMetaData(rows.Scan, &rowData)
		helper.Check(err)
		var metaData models.File
		metaData, err = rowData.ToFileModel()
		helper.Check(err)
		result[metaData.Id] = metaData
	}
	helper.Check(rows.Err())
	return result
}

// GetMetaDataById returns a models.File from the ID passed or false if the id is not valid
func (p DatabaseProvider) GetMetaDataById(id string) (models.File, bool) {
	result := models.File{}
	rowData := schemaMetaData{}

	row := p.queryRow("SELECT "+metaDataColumns+" FROM FileMetaData WHERE Id = $1", id)
	err := scanMetaData(row.Scan, &rowData)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return result, false
		}
		helper.Check(err)
		return result, false
	}
	result, err = rowData.ToFileModel()
	helper.Check(err)
	return result, true
}

// SaveMetaData stores the metadata of a file to the disk
func (p DatabaseProvider) SaveMetaData(file models.File) {
	encryptedName, err := p.encryptNameForSave(file)
	helper.Check(err)
	newData := schemaMetaData{
		Id:                     file.Id,
		NameEncrypted:          encryptedName,
		Size:                   file.Size,
		SHA1:                   file.SHA1,
		ExpireAt:               file.ExpireAt,
		SizeBytes:              file.SizeBytes,
		DownloadsRemaining:     file.DownloadsRemaining,
		DownloadCount:          file.DownloadCount,
		PasswordHash:           file.PasswordHash,
		HotlinkId:              file.HotlinkId,
		ContentType:            file.ContentType,
		AwsBucket:              file.AwsBucket,
		UserId:                 file.UserId,
		UploadDate:             file.UploadDate,
		PendingDeletion:        file.PendingDeletion,
		UploadRequestId:        file.UploadRequestId,
		BundleId:               file.BundleId,
		EncryptedSharePassword: file.EncryptedSharePassword,
		DisposedAt:             file.DisposedAt,
		DisposalReason:         file.DisposalReason,
		WindowOpenedAt:         file.WindowOpenedAt,
	}

	if file.UnlimitedDownloads {
		newData.UnlimitedDownloads = 1
	}
	if file.UnlimitedTime {
		newData.UnlimitedTime = 1
	}

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err = enc.Encode(file.Encryption)
	helper.Check(err)
	newData.Encryption = buf.Bytes()

	_, err = p.exec(`INSERT INTO FileMetaData (Id, NameEncrypted, Size, SHA1, ExpireAt, SizeBytes,
					DownloadsRemaining, DownloadCount, PasswordHash, HotlinkId, ContentType, AwsBucket, Encryption,
					UnlimitedDownloads, UnlimitedTime, UserId, UploadDate, PendingDeletion, UploadRequestId, BundleId,
					EncryptedSharePassword, DisposedAt, DisposalReason, WindowOpenedAt)
					VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24)
					ON CONFLICT (Id) DO UPDATE SET NameEncrypted = EXCLUDED.NameEncrypted, Size = EXCLUDED.Size, SHA1 = EXCLUDED.SHA1,
						ExpireAt = EXCLUDED.ExpireAt, SizeBytes = EXCLUDED.SizeBytes,
						DownloadsRemaining = EXCLUDED.DownloadsRemaining, DownloadCount = EXCLUDED.DownloadCount,
						PasswordHash = EXCLUDED.PasswordHash, HotlinkId = EXCLUDED.HotlinkId,
						ContentType = EXCLUDED.ContentType, AwsBucket = EXCLUDED.AwsBucket,
						Encryption = EXCLUDED.Encryption, UnlimitedDownloads = EXCLUDED.UnlimitedDownloads,
						UnlimitedTime = EXCLUDED.UnlimitedTime, UserId = EXCLUDED.UserId,
						UploadDate = EXCLUDED.UploadDate, PendingDeletion = EXCLUDED.PendingDeletion,
						UploadRequestId = EXCLUDED.UploadRequestId, BundleId = EXCLUDED.BundleId,
						EncryptedSharePassword = EXCLUDED.EncryptedSharePassword,
						DisposedAt = EXCLUDED.DisposedAt, DisposalReason = EXCLUDED.DisposalReason,
						WindowOpenedAt = EXCLUDED.WindowOpenedAt`,
		newData.Id, newData.NameEncrypted, newData.Size, newData.SHA1, newData.ExpireAt, newData.SizeBytes,
		newData.DownloadsRemaining, newData.DownloadCount, newData.PasswordHash, newData.HotlinkId, newData.ContentType,
		newData.AwsBucket, newData.Encryption, newData.UnlimitedDownloads, newData.UnlimitedTime, newData.UserId,
		newData.UploadDate, newData.PendingDeletion, newData.UploadRequestId, newData.BundleId, newData.EncryptedSharePassword,
		newData.DisposedAt, newData.DisposalReason, newData.WindowOpenedAt)
	helper.Check(err)
}

// encryptNameForSave returns the value to store in NameEncrypted for this file. An empty name is
// never a real one - uploads always set one - so it means this models.File was read back while the
// instance was still sealed, when encryption.DecryptFileName had no key and reported the name as
// empty. Re-encrypting that would overwrite the stored name with nothing, which matters because
// bookkeeping writes that are allowed while sealed (marking a file pending deletion, clearing a
// hotlink) go through this same path.
//
// NameEncryptedRaw, if the caller's File model was itself the result of a read, carries the exact
// bytes that were stored for this row (see models.File.NameEncryptedRaw) and is used verbatim -
// this is what makes database.Migrate safe: it runs before the master key is loaded, so it can
// never decrypt an encrypted name into file.Name, but it must still copy the original ciphertext
// rather than lose it. Looking it up in this database is only a fallback for a File model that was
// never read (so carries no raw bytes), kept for the in-place bookkeeping writes this always
// handled correctly before NameEncryptedRaw existed.
func (p DatabaseProvider) encryptNameForSave(file models.File) ([]byte, error) {
	if file.Name != "" {
		return encryption.EncryptFileName(file.Name)
	}
	if file.NameEncryptedRaw != nil {
		return file.NameEncryptedRaw, nil
	}
	var storedName []byte
	row := p.queryRow("SELECT NameEncrypted FROM FileMetaData WHERE Id = $1", file.Id)
	err := row.Scan(&storedName)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return storedName, err
}

// AcquireDownload atomically lets one request through to a capped file's content, in three steps:
// serve free inside an open window, otherwise open a window and spend an allowance, otherwise
// re-check the window because a concurrent caller may have opened one in between. The decrement is
// conditional on DownloadsRemaining > 0, so the database itself refuses to go below zero, and on
// the window still being closed, so two callers cannot both open one.
//
// The third step is what makes two simultaneous first requests on a one-download file both
// succeed: exactly one of them opens the window, the other loses the conditional UPDATE and finds
// the winner's window on the re-check. Without it the loser would be refused, which is the failure
// the window exists to remove.
func (p DatabaseProvider) AcquireDownload(id string, timeNow, leeway int64) (bool, bool) {
	windowOpenSince := timeNow - leeway
	if p.isDownloadWindowOpen(id, windowOpenSince) {
		return true, false
	}
	result, err := p.exec(`UPDATE FileMetaData SET DownloadCount = DownloadCount + 1,
					DownloadsRemaining = DownloadsRemaining - 1, WindowOpenedAt = $1
					WHERE Id = $2 AND DownloadsRemaining > 0 AND WindowOpenedAt <= $3`, timeNow, id, windowOpenSince)
	helper.Check(err)
	rowsAffected, err := result.RowsAffected()
	helper.Check(err)
	if rowsAffected > 0 {
		return true, true
	}
	return p.isDownloadWindowOpen(id, windowOpenSince), false
}

// isDownloadWindowOpen reports whether the file's most recent download window is still open. Read
// with a SELECT rather than the row count of a no-op UPDATE, because this runs on the free path of
// every request inside a window and must not write: an UPDATE would leave a dead tuple behind per
// request, for a check that changes nothing. Reading it separately from the UPDATE that follows is
// safe because WindowOpenedAt only ever moves forward, so a window seen open cannot have closed
// again by the time the caller acts on it.
func (p DatabaseProvider) isDownloadWindowOpen(id string, windowOpenSince int64) bool {
	var windowOpenedAt int64
	row := p.queryRow("SELECT WindowOpenedAt FROM FileMetaData WHERE Id = $1", id)
	err := row.Scan(&windowOpenedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false
		}
		helper.Check(err)
		return false
	}
	return windowOpenedAt > windowOpenSince
}

// IncreaseDownloadCount atomically increases the download count of a file, leaving its allowance
// and its window untouched. Only for a file with UnlimitedDownloads set.
func (p DatabaseProvider) IncreaseDownloadCount(id string) {
	_, err := p.exec(`UPDATE FileMetaData SET DownloadCount = DownloadCount + 1 WHERE Id = $1`, id)
	helper.Check(err)
}

// DeleteMetaData deletes information about a file
func (p DatabaseProvider) DeleteMetaData(id string) {
	_, err := p.exec("DELETE FROM FileMetaData WHERE Id = $1", id)
	helper.Check(err)
}

// MigratePlaintextFileNames re-encrypts every file name, folder name, request name and request
// note still stored in a pre-v22/v23 plaintext column, across FileMetaData, FileBundles and
// UploadRequests, dropping each plaintext column once converted. Returns the total number of
// values migrated across all three tables - see LogFileNameMigration, which reports this as one
// count. It is a separate step rather than part of Upgrade because encrypting needs the master
// key, which an Input-level instance does not have until an administrator unseals it - long after
// the schema ladder has run.
//
// Doing nothing and reporting 0 once every plaintext column is gone is the normal steady state, so
// this is safe to call on every unseal. A run that is interrupted part way resumes on the next
// call: rows already converted are skipped by the respective *Encrypted IS NULL filter, and each
// column is only dropped once none are left.
func (p DatabaseProvider) MigratePlaintextFileNames() int {
	migrated := p.migrateFileMetaDataNames()
	migrated += p.migrateFileBundleNames()
	migrated += p.migrateFileRequestNamesAndNotes()
	return migrated
}

// migrateFileMetaDataNames is MigratePlaintextFileNames' original, file-specific body - see that
// function's comment for the full reasoning.
func (p DatabaseProvider) migrateFileMetaDataNames() int {
	var columnExists bool
	row := p.queryRow(`SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_name = 'filemetadata' AND column_name = 'name')`)
	err := row.Scan(&columnExists)
	helper.Check(err)
	if !columnExists {
		return 0
	}

	rows, err := p.query(`SELECT Id, Name FROM FileMetaData WHERE NameEncrypted IS NULL`)
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
		_, err = p.exec(`UPDATE FileMetaData SET NameEncrypted = $1 WHERE Id = $2`, encryptedName, id)
		helper.Check(err)
	}

	_, err = p.exec(`ALTER TABLE FileMetaData DROP COLUMN Name`)
	helper.Check(err)
	return len(plaintextNames)
}
