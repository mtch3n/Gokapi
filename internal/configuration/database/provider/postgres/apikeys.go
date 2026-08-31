package postgres

import (
	"database/sql"
	"errors"
	"time"

	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
)

type schemaApiKeys struct {
	Id              string
	FriendlyName    string
	LastUsed        int64
	Permissions     int
	Expiry          sql.NullInt64
	IsSystemKey     sql.NullInt64
	UserId          int
	PublicId        string
	UploadRequestId string
}

func (s schemaApiKeys) toApiKey() models.ApiKey {
	return models.ApiKey{
		Id:              s.Id,
		PublicId:        s.PublicId,
		FriendlyName:    s.FriendlyName,
		LastUsed:        s.LastUsed,
		Permissions:     models.ApiPermission(s.Permissions),
		Expiry:          s.Expiry.Int64,
		IsSystemKey:     s.IsSystemKey.Valid && s.IsSystemKey.Int64 == 1,
		UserId:          s.UserId,
		UploadRequestId: s.UploadRequestId,
	}
}

// currentTime is used in order to modify the current time for testing purposes in unit tests
var currentTime = func() time.Time {
	return time.Now()
}

// GetAllApiKeys returns a map with all API keys
func (p DatabaseProvider) GetAllApiKeys() map[string]models.ApiKey {
	result := make(map[string]models.ApiKey)

	rows, err := p.postgresDb.Query("SELECT * FROM ApiKeys WHERE Expiry = 0 OR Expiry IS NULL OR Expiry > $1",
		currentTime().Unix())
	helper.Check(err)
	defer rows.Close()
	for rows.Next() {
		rowData := schemaApiKeys{}
		err = rows.Scan(&rowData.Id, &rowData.FriendlyName, &rowData.LastUsed, &rowData.Permissions, &rowData.Expiry,
			&rowData.IsSystemKey, &rowData.UserId, &rowData.PublicId, &rowData.UploadRequestId)
		helper.Check(err)
		result[rowData.Id] = rowData.toApiKey()
	}
	helper.Check(rows.Err())
	return result
}

// GetApiKey returns a models.ApiKey if valid or false if the ID is not valid
func (p DatabaseProvider) GetApiKey(id string) (models.ApiKey, bool) {
	var rowResult schemaApiKeys
	row := p.postgresDb.QueryRow("SELECT * FROM ApiKeys WHERE Id = $1", id)
	err := row.Scan(&rowResult.Id, &rowResult.FriendlyName, &rowResult.LastUsed, &rowResult.Permissions, &rowResult.Expiry,
		&rowResult.IsSystemKey, &rowResult.UserId, &rowResult.PublicId, &rowResult.UploadRequestId)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.ApiKey{}, false
		}
		helper.Check(err)
		return models.ApiKey{}, false
	}
	return rowResult.toApiKey(), true
}

// GetApiKeyByPublicKey returns an API key by using the public key
func (p DatabaseProvider) GetApiKeyByPublicKey(publicKey string) (string, bool) {
	var rowResult schemaApiKeys
	row := p.postgresDb.QueryRow("SELECT Id FROM ApiKeys WHERE PublicId = $1 LIMIT 1", publicKey)
	err := row.Scan(&rowResult.Id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false
		}
		helper.Check(err)
		return "", false
	}
	return rowResult.Id, true
}

// SaveApiKey saves the API key to the database
func (p DatabaseProvider) SaveApiKey(apikey models.ApiKey) {
	isSystemKey := 0
	if apikey.IsSystemKey {
		isSystemKey = 1
	}
	_, err := p.postgresDb.Exec(`INSERT INTO ApiKeys
					(Id, FriendlyName, LastUsed, Permissions, Expiry, IsSystemKey, UserId, PublicId, UploadRequestId)
					VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
					ON CONFLICT (Id) DO UPDATE SET FriendlyName = EXCLUDED.FriendlyName, LastUsed = EXCLUDED.LastUsed,
						Permissions = EXCLUDED.Permissions, Expiry = EXCLUDED.Expiry, IsSystemKey = EXCLUDED.IsSystemKey,
						UserId = EXCLUDED.UserId, PublicId = EXCLUDED.PublicId, UploadRequestId = EXCLUDED.UploadRequestId`,
		apikey.Id, apikey.FriendlyName, apikey.LastUsed, apikey.Permissions, apikey.Expiry, isSystemKey,
		apikey.UserId, apikey.PublicId, apikey.UploadRequestId)
	helper.Check(err)
}

// UpdateTimeApiKey writes the content of LastUsage to the database
func (p DatabaseProvider) UpdateTimeApiKey(apikey models.ApiKey) {
	_, err := p.postgresDb.Exec("UPDATE ApiKeys SET LastUsed = $1 WHERE Id = $2",
		apikey.LastUsed, apikey.Id)
	helper.Check(err)
}

// DeleteApiKey deletes an API key with the given ID
func (p DatabaseProvider) DeleteApiKey(id string) {
	_, err := p.postgresDb.Exec("DELETE FROM ApiKeys WHERE Id = $1", id)
	helper.Check(err)
}

func (p DatabaseProvider) cleanApiKeys() {
	_, err := p.postgresDb.Exec("DELETE FROM ApiKeys WHERE Expiry > 0 AND Expiry < $1", currentTime().Unix())
	helper.Check(err)
}
