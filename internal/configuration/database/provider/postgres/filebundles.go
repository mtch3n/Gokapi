package postgres

import (
	"database/sql"
	"errors"

	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
)

const fileBundleColumns = "id, name, userid, creationdate, EncryptedSharePassword"

type schemaFileBundle struct {
	Id                     string
	Name                   string
	UserId                 int
	CreationDate           int64
	EncryptedSharePassword []byte
}

func (s schemaFileBundle) toFileBundle() models.FileBundle {
	return models.FileBundle{
		Id:                     s.Id,
		Name:                   s.Name,
		UserId:                 s.UserId,
		CreationDate:           s.CreationDate,
		EncryptedSharePassword: s.EncryptedSharePassword,
	}
}

// GetFileBundle returns the FileBundle or false if not found
func (p DatabaseProvider) GetFileBundle(id string) (models.FileBundle, bool) {
	if id == "" {
		return models.FileBundle{}, false
	}
	var rowResult schemaFileBundle
	row := p.queryRow("SELECT "+fileBundleColumns+" FROM FileBundles WHERE id = $1", id)
	err := row.Scan(&rowResult.Id, &rowResult.Name, &rowResult.UserId, &rowResult.CreationDate, &rowResult.EncryptedSharePassword)
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
	rows, err := p.query("SELECT " + fileBundleColumns + " FROM FileBundles ORDER BY creationdate DESC, name")
	helper.Check(err)
	defer rows.Close()
	for rows.Next() {
		rowData := schemaFileBundle{}
		err = rows.Scan(&rowData.Id, &rowData.Name, &rowData.UserId, &rowData.CreationDate, &rowData.EncryptedSharePassword)
		helper.Check(err)
		result = append(result, rowData.toFileBundle())
	}
	helper.Check(rows.Err())
	return result
}

// SaveFileBundle stores the file bundle in the database
func (p DatabaseProvider) SaveFileBundle(bundle models.FileBundle) {
	newData := schemaFileBundle{
		Id:                     bundle.Id,
		Name:                   bundle.Name,
		UserId:                 bundle.UserId,
		CreationDate:           bundle.CreationDate,
		EncryptedSharePassword: bundle.EncryptedSharePassword,
	}

	_, err := p.exec(`INSERT INTO FileBundles
					(id, name, userid, creationdate, EncryptedSharePassword)
					VALUES ($1, $2, $3, $4, $5)
					ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, userid = EXCLUDED.userid,
						creationdate = EXCLUDED.creationdate, EncryptedSharePassword = EXCLUDED.EncryptedSharePassword`,
		newData.Id, newData.Name, newData.UserId, newData.CreationDate, newData.EncryptedSharePassword)
	helper.Check(err)
}

// DeleteFileBundle deletes a file bundle with the given ID
func (p DatabaseProvider) DeleteFileBundle(bundle models.FileBundle) {
	if bundle.Id == "" {
		return
	}
	_, err := p.exec("DELETE FROM FileBundles WHERE id = $1", bundle.Id)
	helper.Check(err)
}
