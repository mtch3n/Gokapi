package postgres

import (
	"database/sql"
	"errors"
	"time"

	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
)

const userColumns = "Id, Name, Password, Permissions, Userlevel, LastOnline, ResetPassword"

type schemaUser struct {
	Id            int
	Name          string
	Password      sql.NullString
	Permissions   models.UserPermission
	UserLevel     models.UserRank
	LastOnline    int64
	ResetPassword int
}

func (s schemaUser) ToUser() models.User {
	pw := ""
	if s.Password.Valid {
		pw = s.Password.String
	}
	return models.User{
		Id:            s.Id,
		Name:          s.Name,
		Permissions:   s.Permissions,
		UserLevel:     s.UserLevel,
		LastOnline:    s.LastOnline,
		Password:      pw,
		ResetPassword: s.ResetPassword == 1,
	}
}

// GetAllUsers returns a map with all users
func (p DatabaseProvider) GetAllUsers() []models.User {
	var result []models.User
	rows, err := p.postgresDb.Query("SELECT " + userColumns + " FROM Users ORDER BY Userlevel, LastOnline DESC, Name")
	helper.Check(err)
	defer rows.Close()
	for rows.Next() {
		row := schemaUser{}
		err = rows.Scan(&row.Id, &row.Name, &row.Password, &row.Permissions, &row.UserLevel, &row.LastOnline, &row.ResetPassword)
		helper.Check(err)
		result = append(result, row.ToUser())
	}
	helper.Check(rows.Err())
	return result
}

func (p DatabaseProvider) getUserWithConstraint(isName bool, searchValue any) (models.User, bool) {
	rowResult := schemaUser{}
	query := "SELECT " + userColumns + " FROM Users WHERE Id = $1"
	if isName {
		query = "SELECT " + userColumns + " FROM Users WHERE Name = $1"
	}
	row := p.postgresDb.QueryRow(query, searchValue)
	err := row.Scan(&rowResult.Id, &rowResult.Name, &rowResult.Password, &rowResult.Permissions,
		&rowResult.UserLevel, &rowResult.LastOnline, &rowResult.ResetPassword)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.User{}, false
		}
		helper.Check(err)
		return models.User{}, false
	}
	user := rowResult.ToUser()
	return user, true
}

// GetUser returns a models.User if valid or false if the ID is not valid
func (p DatabaseProvider) GetUser(id int) (models.User, bool) {
	return p.getUserWithConstraint(false, id)
}

// GetUserByName returns a models.User if valid or false if the name is not valid
func (p DatabaseProvider) GetUserByName(username string) (models.User, bool) {
	return p.getUserWithConstraint(true, username)
}

// SaveUser saves a user to the database. If isNewUser is true, a new Id will be generated
func (p DatabaseProvider) SaveUser(user models.User, isNewUser bool) {
	resetpw := 0
	if user.ResetPassword {
		resetpw = 1
	}
	if isNewUser {
		_, err := p.postgresDb.Exec(`INSERT INTO Users (Name, Password, Permissions, Userlevel, LastOnline, ResetPassword)
						VALUES ($1, $2, $3, $4, $5, $6)`,
			user.Name, user.Password, user.Permissions, user.UserLevel, user.LastOnline, resetpw)
		helper.Check(err)
		return
	}
	_, err := p.postgresDb.Exec(`INSERT INTO Users (Id, Name, Password, Permissions, Userlevel, LastOnline, ResetPassword)
					VALUES ($1, $2, $3, $4, $5, $6, $7)
					ON CONFLICT (Id) DO UPDATE SET Name = EXCLUDED.Name, Password = EXCLUDED.Password,
						Permissions = EXCLUDED.Permissions, Userlevel = EXCLUDED.Userlevel,
						LastOnline = EXCLUDED.LastOnline, ResetPassword = EXCLUDED.ResetPassword`,
		user.Id, user.Name, user.Password, user.Permissions, user.UserLevel, user.LastOnline, resetpw)
	helper.Check(err)
	p.syncUserIdSequence()
}

// syncUserIdSequence advances the identity sequence past any explicitly inserted Id.
// Rows written with an explicit Id (an update, or a migration from another provider)
// do not advance the sequence, so without this a later generated Id would collide.
func (p DatabaseProvider) syncUserIdSequence() {
	_, err := p.postgresDb.Exec(`SELECT setval(pg_get_serial_sequence('users', 'id'),
					GREATEST(COALESCE((SELECT MAX(Id) FROM Users), 1), 1))`)
	helper.Check(err)
}

// UpdateUserLastOnline writes the last online time to the database
func (p DatabaseProvider) UpdateUserLastOnline(id int) {
	timeNow := time.Now().Unix()
	_, err := p.postgresDb.Exec("UPDATE Users SET LastOnline = $1 WHERE Id = $2", timeNow, id)
	helper.Check(err)
}

// DeleteUser deletes a user with the given ID
func (p DatabaseProvider) DeleteUser(id int) {
	_, err := p.postgresDb.Exec("DELETE FROM Users WHERE Id = $1", id)
	helper.Check(err)
}
