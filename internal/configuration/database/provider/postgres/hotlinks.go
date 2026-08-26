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
	row := p.queryRow("SELECT FileId FROM Hotlinks WHERE Id = $1", id)
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
	rows, err := p.query("SELECT Id FROM Hotlinks")
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

	// FileId carries its own UNIQUE constraint. SQLite's INSERT OR REPLACE drops
	// any row colliding on *any* unique constraint, so clear a stale row for this
	// file first; otherwise ON CONFLICT (Id) would raise a unique violation on
	// FileId instead of replacing, which is a behavioural break from SQLite.
	_, err := p.exec("DELETE FROM Hotlinks WHERE FileId = $1 AND Id <> $2", newData.FileId, newData.Id)
	helper.Check(err)
	_, err = p.exec(`INSERT INTO Hotlinks (Id, FileId) VALUES ($1, $2)
					ON CONFLICT (Id) DO UPDATE SET FileId = EXCLUDED.FileId`,
		newData.Id, newData.FileId)
	helper.Check(err)
}

// DeleteHotlink deletes a hotlink with the given hotlink ID
func (p DatabaseProvider) DeleteHotlink(id string) {
	if id == "" {
		return
	}
	_, err := p.exec("DELETE FROM Hotlinks WHERE Id = $1", id)
	helper.Check(err)
}
