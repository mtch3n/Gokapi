package sqlite

import (
	"bytes"
	"database/sql"
	"encoding/gob"
	"errors"

	"github.com/forceu/gokapi/internal/encryption"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
)

// metaDataColumns is listed explicitly rather than using SELECT *, because the scans below are
// positional. SQLite appends an ALTER TABLE ADD COLUMN at the end of the table and closes the gap
// left by a DROP COLUMN, so an upgraded database orders its columns differently from one created
// fresh from the CREATE TABLE above - which SELECT * would silently scan into the wrong fields.
const metaDataColumns = `Id, NameEncrypted, Size, SHA1, ExpireAt, SizeBytes, DownloadsRemaining, DownloadCount,
	PasswordHash, HotlinkId, ContentType, AwsBucket, Encryption, UnlimitedDownloads, UnlimitedTime,
	UserId, UploadDate, PendingDeletion, UploadRequestId, BundleId, EncryptedSharePassword,
	DisposedAt, DisposalReason`

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
	}

	buf := bytes.NewBuffer(rowData.Encryption)
	dec := gob.NewDecoder(buf)
	err := dec.Decode(&result.Encryption)
	return result, err
}

// GetAllMetadata returns a map of all available files
func (p DatabaseProvider) GetAllMetadata() map[string]models.File {
	result := make(map[string]models.File)
	rows, err := p.sqliteDb.Query("SELECT " + metaDataColumns + " FROM FileMetaData")
	helper.Check(err)
	defer rows.Close()
	for rows.Next() {
		rowData := schemaMetaData{}
		err = rows.Scan(&rowData.Id, &rowData.NameEncrypted, &rowData.Size, &rowData.SHA1, &rowData.ExpireAt, &rowData.SizeBytes,
			&rowData.DownloadsRemaining, &rowData.DownloadCount, &rowData.PasswordHash, &rowData.HotlinkId, &rowData.ContentType,
			&rowData.AwsBucket, &rowData.Encryption, &rowData.UnlimitedDownloads, &rowData.UnlimitedTime, &rowData.UserId,
			&rowData.UploadDate, &rowData.PendingDeletion, &rowData.UploadRequestId, &rowData.BundleId, &rowData.EncryptedSharePassword,
			&rowData.DisposedAt, &rowData.DisposalReason)
		helper.Check(err)
		var metaData models.File
		metaData, err = rowData.ToFileModel()
		helper.Check(err)
		result[metaData.Id] = metaData
	}
	return result
}

// GetMetaDataById returns a models.File from the ID passed or false if the id is not valid
func (p DatabaseProvider) GetMetaDataById(id string) (models.File, bool) {
	result := models.File{}
	rowData := schemaMetaData{}

	row := p.sqliteDb.QueryRow("SELECT "+metaDataColumns+" FROM FileMetaData WHERE Id = ?", id)
	err := row.Scan(&rowData.Id, &rowData.NameEncrypted, &rowData.Size, &rowData.SHA1, &rowData.ExpireAt, &rowData.SizeBytes,
		&rowData.DownloadsRemaining, &rowData.DownloadCount, &rowData.PasswordHash,
		&rowData.HotlinkId, &rowData.ContentType, &rowData.AwsBucket, &rowData.Encryption,
		&rowData.UnlimitedDownloads, &rowData.UnlimitedTime, &rowData.UserId, &rowData.UploadDate,
		&rowData.PendingDeletion, &rowData.UploadRequestId, &rowData.BundleId, &rowData.EncryptedSharePassword,
		&rowData.DisposedAt, &rowData.DisposalReason)
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

	_, err = p.sqliteDb.Exec(`INSERT OR REPLACE INTO FileMetaData (Id, NameEncrypted, Size, SHA1, ExpireAt, SizeBytes,
                                   DownloadsRemaining, DownloadCount, PasswordHash, HotlinkId, ContentType, AwsBucket, Encryption,
                                   UnlimitedDownloads, UnlimitedTime, UserId, UploadDate, PendingDeletion, UploadRequestId, BundleId,
                                   EncryptedSharePassword, DisposedAt, DisposalReason)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		newData.Id, newData.NameEncrypted, newData.Size, newData.SHA1, newData.ExpireAt, newData.SizeBytes,
		newData.DownloadsRemaining, newData.DownloadCount, newData.PasswordHash, newData.HotlinkId, newData.ContentType,
		newData.AwsBucket, newData.Encryption, newData.UnlimitedDownloads, newData.UnlimitedTime, newData.UserId, newData.UploadDate,
		newData.PendingDeletion, newData.UploadRequestId, newData.BundleId, newData.EncryptedSharePassword,
		newData.DisposedAt, newData.DisposalReason)
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
	row := p.sqliteDb.QueryRow("SELECT NameEncrypted FROM FileMetaData WHERE Id = ?", file.Id)
	err := row.Scan(&storedName)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return storedName, err
}

// IncreaseDownloadCount atomically increases the download count of a file. If decreaseRemainingDownloads
// is true, the decrement is conditional on DownloadsRemaining > 0, so the database itself refuses to go
// below zero; the return value reports whether this call actually consumed a remaining download. A false
// return means DownloadsRemaining was already 0 and the caller must not serve the file.
func (p DatabaseProvider) IncreaseDownloadCount(id string, decreaseRemainingDownloads bool) bool {
	if decreaseRemainingDownloads {
		result, err := p.sqliteDb.Exec(`UPDATE FileMetaData SET DownloadCount = DownloadCount + 1,
                        DownloadsRemaining = DownloadsRemaining - 1 WHERE id = ? AND DownloadsRemaining > 0`, id)
		helper.Check(err)
		rowsAffected, err := result.RowsAffected()
		helper.Check(err)
		return rowsAffected > 0
	}
	_, err := p.sqliteDb.Exec(`UPDATE FileMetaData SET DownloadCount = DownloadCount + 1 WHERE id = ?`, id)
	helper.Check(err)
	return true
}

// GetDownloadsRemaining returns the remaining downloads of a file that does not implement UnlimitedDownloads
func (p DatabaseProvider) GetDownloadsRemaining(id string) int {
	var downloadsRemaining int
	row := p.sqliteDb.QueryRow("SELECT DownloadsRemaining FROM FileMetaData WHERE Id = ?", id)
	err := row.Scan(&downloadsRemaining)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0
		}
		helper.Check(err)
		return downloadsRemaining
	}
	return downloadsRemaining
}

// DeleteMetaData deletes information about a file
func (p DatabaseProvider) DeleteMetaData(id string) {
	_, err := p.sqliteDb.Exec("DELETE FROM FileMetaData WHERE Id = ?", id)
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
	if !p.columnExists("FileMetaData", "Name") {
		return 0
	}

	rows, err := p.sqliteDb.Query(`SELECT Id, Name FROM FileMetaData WHERE NameEncrypted IS NULL`)
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
		_, err = p.sqliteDb.Exec(`UPDATE FileMetaData SET NameEncrypted = ? WHERE Id = ?`, encryptedName, id)
		helper.Check(err)
	}

	err = p.rawSqlite(`ALTER TABLE FileMetaData DROP COLUMN "Name"`)
	helper.Check(err)
	return len(plaintextNames)
}
