package sessionmanager

/**
Manages the sessions for the admin user or to access password-protected files
*/

import (
	"net/http"
	"time"

	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/environment"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
)

const lengthSessionId = 60

// IsValidSession checks if the user is submitting a valid session token
// If a valid session is found, useSession will be called
// Returns true if authenticated, otherwise false
func IsValidSession(w http.ResponseWriter, r *http.Request, isOauth bool, OAuthRecheckInterval int) (models.User, bool) {
	cookie, err := r.Cookie("session_token")
	if err == nil {
		sessionString := cookie.Value
		if sessionString != "" {
			session, ok := database.GetSession(sessionString)
			if ok {
				user, userExists := database.GetUser(session.UserId)
				if !userExists {
					return user, false
				}
				return user, useSession(w, sessionString, session, isOauth, OAuthRecheckInterval)
			}
		}
	}
	return models.User{}, false
}

// useSession checks if a session is still valid. It Changes the session string
// if it has been used for more than an hour to limit session hijacking
// Returns true if session is still valid
// Returns false if session is invalid (and deletes it)
// The isOauth passed in by the caller reflects only the current global auth method, which is
// wrong for a hybrid instance: renewal instead uses session.IsOauth, the value recorded when
// this specific session was created, so an OAuth session stays an OAuth session (short-lived,
// rechecked against the provider) across every renewal instead of being laundered into a
// long-lived password session the first time it is renewed. See models.Session.IsOauth.
func useSession(w http.ResponseWriter, id string, session models.Session, isOauth bool, OAuthRecheckInterval int) bool {
	if session.ValidUntil < time.Now().Unix() {
		database.DeleteSession(id)
		return false
	}
	if session.RenewAt < time.Now().Unix() {
		CreateSession(w, session.IsOauth, OAuthRecheckInterval, session.UserId)
		database.DeleteSession(id)
	}
	go database.UpdateUserLastOnline(session.UserId)
	return true
}

// CreateSession creates a new session - called after login with correct username / password
// If sessions parameter is nil, it will be loaded from config
func CreateSession(w http.ResponseWriter, isOauth bool, OAuthRecheckInterval int, userId int) {
	timeExpiry := time.Now().Add(sessionDuration())
	if isOauth {
		timeExpiry = time.Now().Add(time.Duration(OAuthRecheckInterval) * time.Hour)
	}

	sessionString := helper.GenerateRandomString(lengthSessionId)
	database.SaveSession(sessionString, models.Session{
		RenewAt:    time.Now().Add(12 * time.Hour).Unix(),
		ValidUntil: timeExpiry.Unix(),
		UserId:     userId,
		IsOauth:    isOauth,
	})
	writeSessionCookie(w, sessionString, timeExpiry)
}

// LogoutSession logs out user and deletes session.
// Returns true if the session that was logged out had been created by the OAuth callback (see
// models.Session.IsOauth), so the caller can force re-consent on the next login rather than
// allowing a silent prompt=none reauthentication - see authentication.Logout.
func LogoutSession(w http.ResponseWriter, r *http.Request) bool {
	wasOauth := false
	cookie, err := r.Cookie("session_token")
	if err == nil {
		if session, ok := database.GetSession(cookie.Value); ok {
			wasOauth = session.IsOauth
		}
		database.DeleteSession(cookie.Value)
	}
	writeSessionCookie(w, "", time.Now())
	return wasOauth
}

// Writes session cookie to browser
func writeSessionCookie(w http.ResponseWriter, sessionString string, expiry time.Time) {
	c := &http.Cookie{
		Name:     "session_token",
		Value:    sessionString,
		Expires:  expiry,
		HttpOnly: true,
		Secure:   configuration.UsesHttps(),
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, c)
}

// sessionDuration returns the configured lifetime for admin and password-protected-file
// sessions. Does not apply to OAuth2 sessions, which use OAuthRecheckInterval instead.
// Default 7 days
func sessionDuration() time.Duration {
	return time.Duration(environment.New().SessionDurationDays) * 24 * time.Hour
}
