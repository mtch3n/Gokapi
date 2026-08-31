package postgres

import (
	"database/sql"
	"errors"

	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
)

type schemaFileRequests struct {
	Id       string
	Name     string
	UserId   int
	Expiry   int64
	MaxFiles int
	MaxSize  int
	Creation int64
	ApiKey   string
	Note     string
}

func (s schemaFileRequests) toFileRequest() models.FileRequest {
	return models.FileRequest{
		Id:           s.Id,
		Name:         s.Name,
		UserId:       s.UserId,
		MaxFiles:     s.MaxFiles,
		MaxSize:      s.MaxSize,
		Expiry:       s.Expiry,
		CreationDate: s.Creation,
		ApiKey:       s.ApiKey,
		Notes:        s.Note,
	}
}

// GetFileRequest returns the FileRequest or false if not found
func (p DatabaseProvider) GetFileRequest(id string) (models.FileRequest, bool) {
	if id == "" {
		return models.FileRequest{}, false
	}
	var rowResult schemaFileRequests
	row := p.postgresDb.QueryRow("SELECT * FROM UploadRequests WHERE Id = $1", id)
	err := row.Scan(&rowResult.Id, &rowResult.Name, &rowResult.UserId, &rowResult.Expiry,
		&rowResult.MaxFiles, &rowResult.MaxSize, &rowResult.Creation, &rowResult.ApiKey, &rowResult.Note)
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
	rows, err := p.postgresDb.Query("SELECT * FROM UploadRequests ORDER BY Creation DESC, Name")
	helper.Check(err)
	defer rows.Close()
	for rows.Next() {
		rowData := schemaFileRequests{}
		err = rows.Scan(&rowData.Id, &rowData.Name, &rowData.UserId, &rowData.Expiry, &rowData.MaxFiles,
			&rowData.MaxSize, &rowData.Creation, &rowData.ApiKey, &rowData.Note)
		helper.Check(err)
		result = append(result, rowData.toFileRequest())
	}
	helper.Check(rows.Err())
	return result
}

// SaveFileRequest stores the file request associated with the file in the database
func (p DatabaseProvider) SaveFileRequest(request models.FileRequest) {
	newData := schemaFileRequests{
		Id:       request.Id,
		Name:     request.Name,
		UserId:   request.UserId,
		MaxFiles: request.MaxFiles,
		MaxSize:  request.MaxSize,
		Expiry:   request.Expiry,
		Creation: request.CreationDate,
		ApiKey:   request.ApiKey,
		Note:     request.Notes,
	}

	_, err := p.postgresDb.Exec(`INSERT INTO UploadRequests
					(Id, Name, UserId, Expiry, MaxFiles, MaxSize, Creation, ApiKey, Note)
					VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
					ON CONFLICT (Id) DO UPDATE SET Name = EXCLUDED.Name, UserId = EXCLUDED.UserId,
						Expiry = EXCLUDED.Expiry, MaxFiles = EXCLUDED.MaxFiles, MaxSize = EXCLUDED.MaxSize,
						Creation = EXCLUDED.Creation, ApiKey = EXCLUDED.ApiKey, Note = EXCLUDED.Note`,
		newData.Id, newData.Name, newData.UserId, newData.Expiry, newData.MaxFiles, newData.MaxSize,
		newData.Creation, newData.ApiKey, newData.Note)
	helper.Check(err)
}

// DeleteFileRequest deletes a file request with the given ID
func (p DatabaseProvider) DeleteFileRequest(request models.FileRequest) {
	if request.Id == "" {
		return
	}
	_, err := p.postgresDb.Exec("DELETE FROM UploadRequests WHERE Id = $1", request.Id)
	helper.Check(err)
}
