package sqlite

import (
	"database/sql"
	"errors"

	"github.com/forceu/gokapi/internal/encryption"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
)

// fileBundleColumns is listed explicitly rather than using SELECT *, because the scans below are
// positional. SQLite appends an ALTER TABLE ADD COLUMN at the end of the table and closes the gap
// left by a DROP COLUMN, so an upgraded database orders its columns differently from one created
// fresh from the CREATE TABLE above - which SELECT * would silently scan into the wrong fields.
// See metadata.go's metaDataColumns for the same hazard, hit and fixed there first.
const fileBundleColumns = `id, NameEncrypted, userid, creationdate, EncryptedSharePassword,
	PasswordHash, ExpireAt, UnlimitedTime, DownloadsRemaining, UnlimitedDownloads, WindowOpenedAt`

type schemaFileBundles struct {
	Id                     string
	NameEncrypted          []byte
	UserId                 int
	CreationDate           int64
	EncryptedSharePassword []byte
	PasswordHash           string
	ExpireAt               int64
	UnlimitedTime          int
	DownloadsRemaining     int
	UnlimitedDownloads     int
	WindowOpenedAt         int64
}

func (rowData schemaFileBundles) toFileBundleModel() models.FileBundle {
	return models.FileBundle{
		Id:                     rowData.Id,
		Name:                   encryption.DecryptFileName(rowData.NameEncrypted),
		NameEncryptedRaw:       rowData.NameEncrypted,
		UserId:                 rowData.UserId,
		CreationDate:           rowData.CreationDate,
		EncryptedSharePassword: rowData.EncryptedSharePassword,
		PasswordHash:           rowData.PasswordHash,
		ExpireAt:               rowData.ExpireAt,
		UnlimitedTime:          rowData.UnlimitedTime == 1,
		DownloadsRemaining:     rowData.DownloadsRemaining,
		UnlimitedDownloads:     rowData.UnlimitedDownloads == 1,
		WindowOpenedAt:         rowData.WindowOpenedAt,
	}
}

// GetFileBundle returns the FileBundle or false if not found
func (p DatabaseProvider) GetFileBundle(id string) (models.FileBundle, bool) {
	if id == "" {
		return models.FileBundle{}, false
	}
	var rowResult schemaFileBundles
	row := p.sqliteDb.QueryRow("SELECT "+fileBundleColumns+" FROM FileBundles WHERE id = ?", id)
	err := row.Scan(&rowResult.Id, &rowResult.NameEncrypted, &rowResult.UserId, &rowResult.CreationDate, &rowResult.EncryptedSharePassword,
		&rowResult.PasswordHash, &rowResult.ExpireAt, &rowResult.UnlimitedTime, &rowResult.DownloadsRemaining, &rowResult.UnlimitedDownloads,
		&rowResult.WindowOpenedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.FileBundle{}, false
		}
		helper.Check(err)
		return models.FileBundle{}, false
	}
	return rowResult.toFileBundleModel(), true
}

// GetAllFileBundles returns an array with all file bundles, ordered by creation date
func (p DatabaseProvider) GetAllFileBundles() []models.FileBundle {
	result := make([]models.FileBundle, 0)
	// Tie-broken on Id rather than Name: Name is now ciphertext, and ordering by it would be
	// meaningless (and would leak nothing useful, but is pointless work regardless).
	rows, err := p.sqliteDb.Query("SELECT " + fileBundleColumns + " FROM FileBundles ORDER BY CreationDate DESC, Id")
	helper.Check(err)
	defer rows.Close()
	for rows.Next() {
		rowData := schemaFileBundles{}
		err = rows.Scan(&rowData.Id, &rowData.NameEncrypted, &rowData.UserId, &rowData.CreationDate, &rowData.EncryptedSharePassword,
			&rowData.PasswordHash, &rowData.ExpireAt, &rowData.UnlimitedTime, &rowData.DownloadsRemaining, &rowData.UnlimitedDownloads,
			&rowData.WindowOpenedAt)
		helper.Check(err)
		result = append(result, rowData.toFileBundleModel())
	}
	helper.Check(rows.Err())
	return result
}

// SaveFileBundle stores the file bundle in the database
func (p DatabaseProvider) SaveFileBundle(bundle models.FileBundle) {
	encryptedName, err := p.encryptBundleNameForSave(bundle)
	helper.Check(err)
	newData := schemaFileBundles{
		Id:                     bundle.Id,
		NameEncrypted:          encryptedName,
		UserId:                 bundle.UserId,
		CreationDate:           bundle.CreationDate,
		EncryptedSharePassword: bundle.EncryptedSharePassword,
		PasswordHash:           bundle.PasswordHash,
		ExpireAt:               bundle.ExpireAt,
		DownloadsRemaining:     bundle.DownloadsRemaining,
		WindowOpenedAt:         bundle.WindowOpenedAt,
	}
	if bundle.UnlimitedTime {
		newData.UnlimitedTime = 1
	}
	if bundle.UnlimitedDownloads {
		newData.UnlimitedDownloads = 1
	}

	_, err = p.sqliteDb.Exec(`INSERT OR REPLACE INTO FileBundles
   				 (id, NameEncrypted, userid, creationdate, EncryptedSharePassword,
   				  PasswordHash, ExpireAt, UnlimitedTime, DownloadsRemaining, UnlimitedDownloads, WindowOpenedAt)
        			 VALUES  (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		newData.Id, newData.NameEncrypted, newData.UserId, newData.CreationDate, newData.EncryptedSharePassword,
		newData.PasswordHash, newData.ExpireAt, newData.UnlimitedTime, newData.DownloadsRemaining, newData.UnlimitedDownloads,
		newData.WindowOpenedAt)
	helper.Check(err)
}

// AcquireBundleDownload atomically lets one visit through to a bundle's content - mirrors
// metadata.go's AcquireDownload exactly, including its three steps and the reasoning behind each;
// see that function. A bundle has no DownloadCount to increment alongside the allowance it spends.
func (p DatabaseProvider) AcquireBundleDownload(id string, timeNow, leeway int64) (bool, bool) {
	windowOpenSince := timeNow - leeway
	if p.isBundleWindowOpen(id, windowOpenSince) {
		return true, false
	}
	result, err := p.sqliteDb.Exec(`UPDATE FileBundles SET DownloadsRemaining = DownloadsRemaining - 1,
		WindowOpenedAt = ? WHERE id = ? AND DownloadsRemaining > 0 AND WindowOpenedAt <= ?`, timeNow, id, windowOpenSince)
	helper.Check(err)
	rowsAffected, err := result.RowsAffected()
	helper.Check(err)
	if rowsAffected > 0 {
		return true, true
	}
	return p.isBundleWindowOpen(id, windowOpenSince), false
}

// isBundleWindowOpen reports whether the bundle's most recent download window is still open. See
// metadata.go's isDownloadWindowOpen for why this is a SELECT.
func (p DatabaseProvider) isBundleWindowOpen(id string, windowOpenSince int64) bool {
	var windowOpenedAt int64
	row := p.sqliteDb.QueryRow("SELECT WindowOpenedAt FROM FileBundles WHERE id = ?", id)
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

// encryptBundleNameForSave returns the value to store in NameEncrypted for this bundle. Mirrors
// metadata.go's encryptNameForSave exactly - see that comment for the full reasoning. An empty
// name is never a real one - Create always sets one - so it means this models.FileBundle was read
// back while the instance was still sealed, when encryption.DecryptFileName had no key and
// reported the name as empty; re-encrypting that would overwrite the stored name with nothing.
func (p DatabaseProvider) encryptBundleNameForSave(bundle models.FileBundle) ([]byte, error) {
	if bundle.Name != "" {
		return encryption.EncryptFileName(bundle.Name)
	}
	if bundle.NameEncryptedRaw != nil {
		return bundle.NameEncryptedRaw, nil
	}
	var storedName []byte
	row := p.sqliteDb.QueryRow("SELECT NameEncrypted FROM FileBundles WHERE id = ?", bundle.Id)
	err := row.Scan(&storedName)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return storedName, err
}

// DeleteFileBundle deletes a file bundle with the given ID
func (p DatabaseProvider) DeleteFileBundle(bundle models.FileBundle) {
	if bundle.Id == "" {
		return
	}
	_, err := p.sqliteDb.Exec("DELETE FROM FileBundles WHERE id = ?", bundle.Id)
	helper.Check(err)
}

// migrateFileBundleNames re-encrypts every bundle name still stored in the pre-v23 plaintext name
// column and then drops that column, reporting how many rows it converted. Same shape as
// metadata.go's MigratePlaintextFileNames - see that comment for why this cannot run from
// Upgrade, and why re-running it is a safe no-op.
func (p DatabaseProvider) migrateFileBundleNames() int {
	if !p.columnExists("FileBundles", "name") {
		return 0
	}

	rows, err := p.sqliteDb.Query(`SELECT id, name FROM FileBundles WHERE NameEncrypted IS NULL`)
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
		_, err = p.sqliteDb.Exec(`UPDATE FileBundles SET NameEncrypted = ? WHERE id = ?`, encryptedName, id)
		helper.Check(err)
	}

	err = p.rawSqlite(`ALTER TABLE FileBundles DROP COLUMN "name"`)
	helper.Check(err)
	return len(plaintextNames)
}
