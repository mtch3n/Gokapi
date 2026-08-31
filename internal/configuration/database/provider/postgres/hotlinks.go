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

	// Both Id and FileId carry a UNIQUE constraint, and SQLite's INSERT OR REPLACE
	// drops any row colliding on either of them. Reproducing that needs the delete
	// and the insert in one transaction, otherwise a failure between them leaves the
	// file without a hotlink. The lock serialises concurrent writers, which would
	// otherwise both delete and then collide on the remaining constraint.
	tx, err := p.postgresDb.Begin()
	helper.Check(err)
	defer tx.Rollback()

	_, err = tx.Exec("LOCK TABLE Hotlinks IN SHARE ROW EXCLUSIVE MODE")
	helper.Check(err)
	_, err = tx.Exec("DELETE FROM Hotlinks WHERE Id = $1 OR FileId = $2", newData.Id, newData.FileId)
	helper.Check(err)
	_, err = tx.Exec("INSERT INTO Hotlinks (Id, FileId) VALUES ($1, $2)", newData.Id, newData.FileId)
	helper.Check(err)
	helper.Check(tx.Commit())
}

// DeleteHotlink deletes a hotlink with the given hotlink ID
func (p DatabaseProvider) DeleteHotlink(id string) {
	if id == "" {
		return
	}
	_, err := p.postgresDb.Exec("DELETE FROM Hotlinks WHERE Id = $1", id)
	helper.Check(err)
}
