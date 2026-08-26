package postgres

import (
	"database/sql"
	"errors"

	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
)

type schemaHotlinks struct {
	Id     string
	FileId string
}

// GetHotlink returns the id of the file associated or false if not found
func (p DatabaseProvider) GetHotlink(id string) (string, bool) {
	var rowResult schemaHotlinks
	row := p.postgresDb.QueryRow("SELECT FileId FROM Hotlinks WHERE Id = $1", id)
	err := row.Scan(&rowResult.FileId)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false
		}
		helper.Check(err)
		return "", false
	}
	return rowResult.FileId, true
}

// GetAllHotlinks returns an array with all hotlink ids
func (p DatabaseProvider) GetAllHotlinks() []string {
	ids := make([]string, 0)
	rows, err := p.postgresDb.Query("SELECT Id FROM Hotlinks")
	helper.Check(err)
	defer rows.Close()
	for rows.Next() {
		rowData := schemaHotlinks{}
		err = rows.Scan(&rowData.Id)
		helper.Check(err)
		ids = append(ids, rowData.Id)
	}
	helper.Check(rows.Err())
	return ids
}

// SaveHotlink stores the hotlink associated with the file in the database
func (p DatabaseProvider) SaveHotlink(file models.File) {
	newData := schemaHotlinks{
		Id:     file.HotlinkId,
		FileId: file.Id,
	}

	_, err := p.postgresDb.Exec(`INSERT INTO Hotlinks (Id, FileId) VALUES ($1, $2)
					ON CONFLICT (Id) DO UPDATE SET FileId = EXCLUDED.FileId`,
		newData.Id, newData.FileId)
	helper.Check(err)
}

// DeleteHotlink deletes a hotlink with the given hotlink ID
func (p DatabaseProvider) DeleteHotlink(id string) {
	if id == "" {
		return
	}
	_, err := p.postgresDb.Exec("DELETE FROM Hotlinks WHERE Id = $1", id)
	helper.Check(err)
}
