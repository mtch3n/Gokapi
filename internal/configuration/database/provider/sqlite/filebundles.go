package sqlite

import (
	"database/sql"
	"errors"

	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
)

type schemaFileBundles struct {
	Id                     string
	Name                   string
	UserId                 int
	CreationDate           int64
	EncryptedSharePassword []byte
}

// GetFileBundle returns the FileBundle or false if not found
func (p DatabaseProvider) GetFileBundle(id string) (models.FileBundle, bool) {
	if id == "" {
		return models.FileBundle{}, false
	}
	var rowResult schemaFileBundles
	row := p.sqliteDb.QueryRow("SELECT * FROM FileBundles WHERE id = ?", id)
	err := row.Scan(&rowResult.Id, &rowResult.Name, &rowResult.UserId, &rowResult.CreationDate, &rowResult.EncryptedSharePassword)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.FileBundle{}, false
		}
		helper.Check(err)
		return models.FileBundle{}, false
	}
	result := models.FileBundle{
		Id:                     rowResult.Id,
		Name:                   rowResult.Name,
		UserId:                 rowResult.UserId,
		CreationDate:           rowResult.CreationDate,
		EncryptedSharePassword: rowResult.EncryptedSharePassword,
	}
	return result, true
}

// GetAllFileBundles returns an array with all file bundles, ordered by creation date
func (p DatabaseProvider) GetAllFileBundles() []models.FileBundle {
	result := make([]models.FileBundle, 0)
	rows, err := p.sqliteDb.Query("SELECT * FROM FileBundles ORDER BY CreationDate DESC, Name")
	helper.Check(err)
	defer rows.Close()
	for rows.Next() {
		rowData := schemaFileBundles{}
		err = rows.Scan(&rowData.Id, &rowData.Name, &rowData.UserId, &rowData.CreationDate, &rowData.EncryptedSharePassword)
		helper.Check(err)
		result = append(result, models.FileBundle{
			Id:                     rowData.Id,
			Name:                   rowData.Name,
			UserId:                 rowData.UserId,
			CreationDate:           rowData.CreationDate,
			EncryptedSharePassword: rowData.EncryptedSharePassword,
		})
	}
	helper.Check(rows.Err())
	return result
}

// SaveFileBundle stores the file bundle in the database
func (p DatabaseProvider) SaveFileBundle(bundle models.FileBundle) {
	newData := schemaFileBundles{
		Id:                     bundle.Id,
		Name:                   bundle.Name,
		UserId:                 bundle.UserId,
		CreationDate:           bundle.CreationDate,
		EncryptedSharePassword: bundle.EncryptedSharePassword,
	}

	_, err := p.sqliteDb.Exec(`INSERT OR REPLACE INTO FileBundles
   				 (id, name, userid, creationdate, EncryptedSharePassword)
         			 VALUES  (?, ?, ?, ?, ?)`,
		newData.Id, newData.Name, newData.UserId, newData.CreationDate, newData.EncryptedSharePassword)
	helper.Check(err)
}

// DeleteFileBundle deletes a file bundle with the given ID
func (p DatabaseProvider) DeleteFileBundle(bundle models.FileBundle) {
	if bundle.Id == "" {
		return
	}
	_, err := p.sqliteDb.Exec("DELETE FROM FileBundles WHERE id = ?", bundle.Id)
	helper.Check(err)
}
