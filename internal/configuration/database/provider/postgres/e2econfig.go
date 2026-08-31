package postgres

import (
	"bytes"
	"database/sql"
	"encoding/gob"
	"errors"

	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
)

type schemaE2EConfig struct {
	Id     int64
	Config []byte
	UserId int
}

// SaveEnd2EndInfo stores the encrypted e2e info
func (p DatabaseProvider) SaveEnd2EndInfo(info models.E2EInfoEncrypted, userId int) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(info)
	helper.Check(err)

	_, err = p.postgresDb.Exec(`INSERT INTO E2EConfig (Config, UserId) VALUES ($1, $2)
					ON CONFLICT (UserId) DO UPDATE SET Config = EXCLUDED.Config`,
		buf.Bytes(), userId)
	helper.Check(err)
}

// GetEnd2EndInfo retrieves the encrypted e2e info
func (p DatabaseProvider) GetEnd2EndInfo(userId int) models.E2EInfoEncrypted {
	result := models.E2EInfoEncrypted{}
	rowResult := schemaE2EConfig{}

	row := p.postgresDb.QueryRow("SELECT Config FROM E2EConfig WHERE UserId = $1", userId)
	err := row.Scan(&rowResult.Config)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return result
		}
		helper.Check(err)
		return result
	}

	buf := bytes.NewBuffer(rowResult.Config)
	dec := gob.NewDecoder(buf)
	err = dec.Decode(&result)
	helper.Check(err)
	return result
}

// DeleteEnd2EndInfo resets the encrypted e2e info
func (p DatabaseProvider) DeleteEnd2EndInfo(userId int) {
	_, err := p.postgresDb.Exec("DELETE FROM E2EConfig WHERE UserId = $1", userId)
	helper.Check(err)
}
