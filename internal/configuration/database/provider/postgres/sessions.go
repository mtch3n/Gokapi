package postgres

import (
	"database/sql"
	"errors"
	"time"

	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
)

type schemaSessions struct {
	Id         string
	RenewAt    int64
	ValidUntil int64
	UserId     int
	IsOauth    bool
}

// GetSession returns the session with the given ID or false if not a valid ID
func (p DatabaseProvider) GetSession(id string) (models.Session, bool) {
	var rowResult schemaSessions
	row := p.queryRow("SELECT Id, RenewAt, ValidUntil, UserId, IsOauth FROM Sessions WHERE Id = $1", id)
	err := row.Scan(&rowResult.Id, &rowResult.RenewAt, &rowResult.ValidUntil, &rowResult.UserId, &rowResult.IsOauth)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.Session{}, false
		}
		helper.Check(err)
		return models.Session{}, false
	}
	result := models.Session{
		RenewAt:    rowResult.RenewAt,
		ValidUntil: rowResult.ValidUntil,
		UserId:     rowResult.UserId,
		IsOauth:    rowResult.IsOauth,
	}
	return result, true
}

// SaveSession stores the given session. After the expiry passed, it will be deleted automatically
func (p DatabaseProvider) SaveSession(id string, session models.Session) {
	newData := schemaSessions{
		Id:         id,
		RenewAt:    session.RenewAt,
		ValidUntil: session.ValidUntil,
		UserId:     session.UserId,
		IsOauth:    session.IsOauth,
	}

	_, err := p.exec(`INSERT INTO Sessions (Id, RenewAt, ValidUntil, UserId, IsOauth) VALUES ($1, $2, $3, $4, $5)
					ON CONFLICT (Id) DO UPDATE SET RenewAt = EXCLUDED.RenewAt,
						ValidUntil = EXCLUDED.ValidUntil, UserId = EXCLUDED.UserId, IsOauth = EXCLUDED.IsOauth`,
		newData.Id, newData.RenewAt, newData.ValidUntil, newData.UserId, newData.IsOauth)
	helper.Check(err)
}

// DeleteSession deletes a session with the given ID
func (p DatabaseProvider) DeleteSession(id string) {
	_, err := p.exec("DELETE FROM Sessions WHERE Id = $1", id)
	helper.Check(err)
}

// DeleteAllSessions logs all users out
func (p DatabaseProvider) DeleteAllSessions() {
	//goland:noinspection SqlWithoutWhere
	_, err := p.exec("DELETE FROM Sessions")
	helper.Check(err)
}

// DeleteAllSessionsByUser logs the specific users out
func (p DatabaseProvider) DeleteAllSessionsByUser(userId int) {
	_, err := p.exec("DELETE FROM Sessions WHERE UserId = $1", userId)
	helper.Check(err)
}

func (p DatabaseProvider) cleanExpiredSessions() {
	_, err := p.exec("DELETE FROM Sessions WHERE ValidUntil < $1", time.Now().Unix())
	helper.Check(err)
}
