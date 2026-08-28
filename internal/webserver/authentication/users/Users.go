package users

import (
	"errors"

	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/models"
)

const minLengthUser = 2

// ErrorNameToShort is returned when the username is too short
var ErrorNameToShort = errors.New("username too short")

// ErrorUserExists is returned when the user already exists
var ErrorUserExists = errors.New("user already exists")

// Create creates a new user and returns an error if the user already exists or the username is too short
// provider should be "internal" for internal auth or "google" for OAuth. oidcSubject is only used for OAuth.
func Create(name string, provider string, oidcSubject string) (models.User, error) {
	if len(name) < minLengthUser {
		return models.User{}, ErrorNameToShort
	}
	_, ok := database.GetUserByName(name)
	if ok {
		return models.User{}, ErrorUserExists
	}
	newUser := models.User{
		Name:         name,
		UserLevel:    models.UserLevelUser,
		AuthProvider: provider,
		OidcSubject:  oidcSubject,
	}
	if configuration.GetEnvironment().PermRequestGrantedByDefault {
		newUser.GrantPermission(models.UserPermGuestUploads)
	}
	database.SaveUser(newUser, true)
	newUser, ok = database.GetUserByName(name)
	if !ok {
		return models.User{}, errors.New("user could not be created")
	}
	return newUser, nil
}
