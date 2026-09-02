package postgres

import (
	"database/sql"
	"errors"

	"github.com/forceu/gokapi/internal/encryption"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
)

const fileBundleColumns = `id, NameEncrypted, userid, creationdate, EncryptedSharePassword,
	PasswordHash, ExpireAt, UnlimitedTime, DownloadsRemaining, UnlimitedDownloads`

type schemaFileBundle struct {
	Id                     string
	NameEncrypted          []byte
	UserId                 int
	CreationDate           int64
	EncryptedSharePassword []byte
	PasswordHash           string
	ExpireAt               int64
	UnlimitedTime          bool
	DownloadsRemaining     int
	UnlimitedDownloads     bool
}

func (s schemaFileBundle) toFileBundle() models.FileBundle {
	return models.FileBundle{
		Id:                     s.Id,
		Name:                   encryption.DecryptFileName(s.NameEncrypted),
		NameEncryptedRaw:       s.NameEncrypted,
		UserId:                 s.UserId,
		CreationDate:           s.CreationDate,
		EncryptedSharePassword: s.EncryptedSharePassword,
		PasswordHash:           s.PasswordHash,
		ExpireAt:               s.ExpireAt,
		UnlimitedTime:          s.UnlimitedTime,
		DownloadsRemaining:     s.DownloadsRemaining,
		UnlimitedDownloads:     s.UnlimitedDownloads,
	}
}

// GetFileBundle returns the FileBundle or false if not found
func (p DatabaseProvider) GetFileBundle(id string) (models.FileBundle, bool) {
	if id == "" {
		return models.FileBundle{}, false
	}
	var rowResult schemaFileBundle
	row := p.queryRow("SELECT "+fileBundleColumns+" FROM FileBundles WHERE id = $1", id)
	err := row.Scan(&rowResult.Id, &rowResult.NameEncrypted, &rowResult.UserId, &rowResult.CreationDate, &rowResult.EncryptedSharePassword,
		&rowResult.PasswordHash, &rowResult.ExpireAt, &rowResult.UnlimitedTime, &rowResult.DownloadsRemaining, &rowResult.UnlimitedDownloads)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.FileBundle{}, false
		}
		helper.Check(err)
		return models.FileBundle{}, false
	}
	return rowResult.toFileBundle(), true
}

// GetAllFileBundles returns an array with all file bundles, ordered by creation date
func (p DatabaseProvider) GetAllFileBundles() []models.FileBundle {
	result := make([]models.FileBundle, 0)
	// Tie-broken on id rather than name: name is now ciphertext, and ordering by it would be
	// meaningless.
	rows, err := p.query("SELECT " + fileBundleColumns + " FROM FileBundles ORDER BY creationdate DESC, id")
	helper.Check(err)
	defer rows.Close()
	for rows.Next() {
		rowData := schemaFileBundle{}
		err = rows.Scan(&rowData.Id, &rowData.NameEncrypted, &rowData.UserId, &rowData.CreationDate, &rowData.EncryptedSharePassword,
			&rowData.PasswordHash, &rowData.ExpireAt, &rowData.UnlimitedTime, &rowData.DownloadsRemaining, &rowData.UnlimitedDownloads)
		helper.Check(err)
		result = append(result, rowData.toFileBundle())
	}
	helper.Check(rows.Err())
	return result
}

// SaveFileBundle stores the file bundle in the database
func (p DatabaseProvider) SaveFileBundle(bundle models.FileBundle) {
	encryptedName, err := p.encryptBundleNameForSave(bundle)
	helper.Check(err)
	newData := schemaFileBundle{
		Id:                     bundle.Id,
		NameEncrypted:          encryptedName,
		UserId:                 bundle.UserId,
		CreationDate:           bundle.CreationDate,
		EncryptedSharePassword: bundle.EncryptedSharePassword,
		PasswordHash:           bundle.PasswordHash,
		ExpireAt:               bundle.ExpireAt,
		UnlimitedTime:          bundle.UnlimitedTime,
		DownloadsRemaining:     bundle.DownloadsRemaining,
		UnlimitedDownloads:     bundle.UnlimitedDownloads,
	}

	_, err = p.exec(`INSERT INTO FileBundles
					(id, NameEncrypted, userid, creationdate, EncryptedSharePassword,
					 PasswordHash, ExpireAt, UnlimitedTime, DownloadsRemaining, UnlimitedDownloads)
					VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
					ON CONFLICT (id) DO UPDATE SET NameEncrypted = EXCLUDED.NameEncrypted, userid = EXCLUDED.userid,
						creationdate = EXCLUDED.creationdate, EncryptedSharePassword = EXCLUDED.EncryptedSharePassword,
						PasswordHash = EXCLUDED.PasswordHash, ExpireAt = EXCLUDED.ExpireAt,
						UnlimitedTime = EXCLUDED.UnlimitedTime, DownloadsRemaining = EXCLUDED.DownloadsRemaining,
						UnlimitedDownloads = EXCLUDED.UnlimitedDownloads`,
		newData.Id, newData.NameEncrypted, newData.UserId, newData.CreationDate, newData.EncryptedSharePassword,
		newData.PasswordHash, newData.ExpireAt, newData.UnlimitedTime, newData.DownloadsRemaining, newData.UnlimitedDownloads)
	helper.Check(err)
}

// DecreaseBundleDownloadsRemaining atomically spends one of the bundle's own download allowance,
// conditional on it being greater than 0 - mirrors metadata.go's IncreaseDownloadCount decrement
// half. Returns false, and leaves the allowance untouched, if it was already exhausted.
func (p DatabaseProvider) DecreaseBundleDownloadsRemaining(id string) bool {
	result, err := p.exec(`UPDATE FileBundles SET DownloadsRemaining = DownloadsRemaining - 1
		WHERE id = $1 AND DownloadsRemaining > 0`, id)
	helper.Check(err)
	rowsAffected, err := result.RowsAffected()
	helper.Check(err)
	return rowsAffected > 0
}

// encryptBundleNameForSave returns the value to store in NameEncrypted for this bundle. Mirrors
// metadata.go's encryptNameForSave exactly - see that comment for the full reasoning. An empty
// name is never a real one - Create always sets one - so it means this models.FileBundle was read
// back while the instance was still sealed.
func (p DatabaseProvider) encryptBundleNameForSave(bundle models.FileBundle) ([]byte, error) {
	if bundle.Name != "" {
		return encryption.EncryptFileName(bundle.Name)
	}
	if bundle.NameEncryptedRaw != nil {
		return bundle.NameEncryptedRaw, nil
	}
	var storedName []byte
	row := p.queryRow("SELECT NameEncrypted FROM FileBundles WHERE id = $1", bundle.Id)
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
	_, err := p.exec("DELETE FROM FileBundles WHERE id = $1", bundle.Id)
	helper.Check(err)
}

// migrateFileBundleNames re-encrypts every bundle name still stored in the pre-v23 plaintext name
// column and then drops that column, reporting how many rows it converted. Same shape as
// metadata.go's MigratePlaintextFileNames.
func (p DatabaseProvider) migrateFileBundleNames() int {
	var columnExists bool
	row := p.queryRow(`SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_name = 'filebundles' AND column_name = 'name')`)
	err := row.Scan(&columnExists)
	helper.Check(err)
	if !columnExists {
		return 0
	}

	rows, err := p.query(`SELECT id, name FROM FileBundles WHERE NameEncrypted IS NULL`)
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
		_, err = p.exec(`UPDATE FileBundles SET NameEncrypted = $1 WHERE id = $2`, encryptedName, id)
		helper.Check(err)
	}

	_, err = p.exec(`ALTER TABLE FileBundles DROP COLUMN name`)
	helper.Check(err)
	return len(plaintextNames)
}
