package authentication

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/logging"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/webserver/authentication/csrftoken"
	"github.com/forceu/gokapi/internal/webserver/authentication/sessionmanager"
	"github.com/forceu/gokapi/internal/webserver/authentication/users"
	"github.com/forceu/gokapi/internal/webserver/errorHandling"
)

type userNameContext string

// CookieOauth is the cookie name used for login
const CookieOauth = "state"

const userNameContextKey userNameContext = "userName"

var authSettings models.AuthenticationConfig

// Init needs to be called first to process the authentication configuration
func Init(config models.AuthenticationConfig) {
	err := checkAuthConfig(config)
	if err != nil {
		log.Println("Error while initiating authentication method:")
		log.Println(err)
		osExit(3)
		return
	}
	authSettings = config
}

var osExit = os.Exit

// checkAuthConfig checks if the config is actually valid, and returns an error otherwise
func checkAuthConfig(config models.AuthenticationConfig) error {
	switch config.Method {
	case models.AuthenticationInternal:
		if len(config.Username) < 3 {
			return errors.New("username too short")
		}
		// In hybrid mode, also validate OAuth fields
		if config.OAuthEnabledAlongsideInternal {
			if config.OAuthProvider == "" {
				return errors.New("oauth provider was not set")
			}
			if config.OAuthClientId == "" {
				return errors.New("oauth client id was not set")
			}
			if config.OAuthClientSecret == "" {
				return errors.New("oauth client secret was not set")
			}
			if config.OAuthRecheckInterval < 1 {
				return errors.New("oauth recheck interval invalid")
			}
		}
		return nil
	case models.AuthenticationOAuth2:
		if config.OAuthProvider == "" {
			return errors.New("oauth provider was not set")
		}
		if config.OAuthClientId == "" {
			return errors.New("oauth client id was not set")
		}
		if config.OAuthClientSecret == "" {
			return errors.New("oauth client secret was not set")
		}
		if config.OAuthRecheckInterval < 1 {
			return errors.New("oauth recheck interval invalid")
		}
		return nil
	case models.AuthenticationHeader:
		if config.HeaderKey == "" {
			return errors.New("header key is not set")
		}
		return nil
	case models.AuthenticationDisabled:
		return nil
	default:
		return errors.New("unknown authentication selected")
	}
}

// GetUserFromRequest returns the user that has been authenticated with the request
func GetUserFromRequest(r *http.Request) (models.User, error) {
	c := r.Context()
	user, ok := c.Value(userNameContextKey).(models.User)
	if !ok {
		return models.User{}, errors.New("user not found in context")
	}
	return user, nil
}

// SetUserInRequest saves the user that has been authenticated with the request
func SetUserInRequest(r *http.Request, user models.User) *http.Request {
	c := context.WithValue(r.Context(), userNameContextKey, user)
	return r.WithContext(c)
}

// IsAuthenticated returns true and the user ID if authenticated
func IsAuthenticated(w http.ResponseWriter, r *http.Request) (models.User, bool, error) {
	switch authSettings.Method {
	case models.AuthenticationInternal:
		user, ok := isGrantedSession(w, r)
		if ok {
			return user, true, nil
		}
	case models.AuthenticationOAuth2:
		user, ok := isGrantedSession(w, r)
		if ok {
			return user, true, nil
		}
	case models.AuthenticationHeader:
		user, ok, err := isGrantedHeader(r)
		if err != nil {
			return models.User{}, false, err
		}
		if ok {
			return user, true, nil
		}
	case models.AuthenticationDisabled:
		adminUser, ok := database.GetSuperAdmin()
		if !ok {
			panic("no super admin found")
		}
		return adminUser, true, nil
	}
	return models.User{}, false, nil
}

// isGrantedHeader returns true if the user was authenticated by a proxy header if enabled
func isGrantedHeader(r *http.Request) (models.User, bool, error) {
	if authSettings.HeaderKey == "" {
		return models.User{}, false, errors.New("header key is not set")
	}
	userName := r.Header.Get(authSettings.HeaderKey)
	if userName == "" {
		return models.User{}, false, errors.New("header key is not set or empty")
	}
	return getOrCreateUser(userName, models.AuthProviderInternal, "")
}

func matchesWithWildcard(pattern, input string) (bool, error) {
	components := strings.Split(pattern, "*")
	if len(components) == 1 {
		// if len is 1, there are no *'s, return exact match pattern
		return strings.ToLower(pattern) == strings.ToLower(input), nil
	}
	var result strings.Builder
	for i, literal := range components {
		// Replace * with .*
		if i > 0 {
			result.WriteString(".*")
		}
		// Quote any regular expression meta characters in the
		// literal text.
		result.WriteString(regexp.QuoteMeta(literal))
	}
	return regexp.MatchString("^"+result.String()+"$", input)
}

func isGroupInArray(userGroups []string, allowedGroups []string) bool {
	for _, group := range userGroups {
		for _, allowedGroup := range allowedGroups {
			matches, err := matchesWithWildcard(strings.ToLower(allowedGroup), strings.ToLower(group))
			helper.Check(err)
			if matches {
				return true
			}
		}
	}
	return false
}

func extractOauthGroups(userInfo OAuthUserClaims, groupScope string) ([]string, error) {
	var claims json.RawMessage
	var data map[string]interface{}

	err := userInfo.Claims(&claims)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(claims, &data)
	if err != nil {
		return nil, err
	}

	// Extract the "groups" field
	groupsInterface, ok := data[groupScope]
	if !ok {
		return nil, fmt.Errorf("claim %s was not passed on", groupScope)
	}

	// Handle both string and array cases
	var groups []string
	switch v := groupsInterface.(type) {
	case string:
		groups = append(groups, v)
	case []any:
		for _, group := range v {
			groupString, isValid := group.(string)
			if isValid {
				groups = append(groups, groupString)
			}
		}
	default:
		return nil, fmt.Errorf("scope %s is not a valid type", groupScope)
	}

	return groups, nil
}

// OAuthUserInfo is used to make testing easier. This results in an additional parameter for the subject unfortunately
type OAuthUserInfo struct {
	Subject    string
	Email      string
	ClaimsSent OAuthUserClaims
}

// OAuthUserClaims contains the claims
type OAuthUserClaims interface {
	Claims(v interface{}) error
}

// CheckOauthUserAndRedirect checks if the user is allowed to use the Gokapi instance
func CheckOauthUserAndRedirect(w http.ResponseWriter, r *http.Request, userInfo OAuthUserInfo) error {
	var groups []string
	var err error

	// Require email_verified claim to be true when present
	if err := checkEmailVerified(userInfo.ClaimsSent); err != nil {
		return err
	}

	if authSettings.OAuthGroupScope != "" {
		groups, err = extractOauthGroups(userInfo.ClaimsSent, authSettings.OAuthGroupScope)
		if err != nil {
			return err
		}
	}
	if isValidOauthUser(userInfo, groups) {
		user, ok, errCreate := getOrCreateUser(userInfo.Email, models.AuthProviderGoogle, userInfo.Subject)
		if errCreate != nil {
			return errCreate
		}
		if ok {
			sessionmanager.CreateSession(w, true, authSettings.OAuthRecheckInterval, user.Id)
			logging.LogValidLogin(userInfo.Email, userInfo.Subject, logging.GetIpAddress(r))
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return nil
		}
	}
	logging.LogInvalidLogin(userInfo.Email, logging.GetIpAddress(r))
	errorHandling.RedirectGenericErrorPage(w, r, errorHandling.TypeOAuthNotAuthorised)
	return nil
}

// getOrCreateUser handles provider-aware user binding.
// For OAuth/OIDC (provider == models.AuthProviderGoogle): this is an ALLOW-LIST. A row is only
// ever authenticated through this path if it was deliberately provisioned for OIDC, i.e. its
// stored AuthProvider is already models.AuthProviderGoogle. An empty, "internal", or any other
// AuthProvider is rejected outright - this is what stops a Google login for the super admin's
// (or any internal user's) email address from silently taking over that account. Within a row
// that is allowed, the OidcSubject is either bound on first use (a row that was provisioned for
// OIDC but never logged in yet) or must match exactly on every later login; a mismatch (e.g. a
// corporate email address reassigned to a different person in Google) is rejected too.
// For internal/header auth: matches by username only, unchanged.
func getOrCreateUser(username, provider, oidcSubject string) (models.User, bool, error) {
	user, ok := database.GetUserByName(username)
	if ok {
		if provider == models.AuthProviderGoogle {
			if user.AuthProvider != models.AuthProviderGoogle {
				// Not a row deliberately provisioned for OIDC: reject regardless of whether
				// AuthProvider is empty, "internal", or anything else. This is the account
				// takeover guard.
				return models.User{}, false, nil
			}
			if user.OidcSubject == "" {
				// First-time binding on a row that was deliberately provisioned for OIDC.
				user.OidcSubject = oidcSubject
				database.SaveUser(user, false)
			} else if user.OidcSubject != oidcSubject {
				// A different subject is presented for the same email - e.g. a reassigned
				// corporate mailbox - must not inherit the previous owner's account.
				return models.User{}, false, nil
			}
		}
		return user, true, nil
	}
	if authSettings.OnlyRegisteredUsers {
		return models.User{}, false, nil
	}
	newUser, err := users.Create(username, provider, oidcSubject)
	if err != nil {
		return models.User{}, false, err
	}
	return newUser, true, nil
}

// checkEmailVerified extracts and validates the email_verified claim
func checkEmailVerified(claims OAuthUserClaims) error {
	var rawClaims json.RawMessage
	var data map[string]interface{}

	err := claims.Claims(&rawClaims)
	if err != nil {
		return err
	}
	err = json.Unmarshal(rawClaims, &data)
	if err != nil {
		return err
	}

	// Check if email_verified claim exists
	if emailVerified, exists := data["email_verified"]; exists {
		// If it exists, it must be true
		if verified, ok := emailVerified.(bool); !ok {
			// If it's not a bool, consider it an error
			return errors.New("email_verified claim is not a boolean")
		} else if !verified {
			return errors.New("email_verified claim is false")
		}
	}
	// If email_verified doesn't exist, we don't require it (provider may not send it)
	return nil
}

func isValidOauthUser(userInfo OAuthUserInfo, groups []string) bool {
	if userInfo.Subject == "" {
		return false
	}
	if userInfo.Email == "" {
		return false
	}
	isValidGroup := true
	if len(authSettings.OAuthGroups) > 0 {
		isValidGroup = isGroupInArray(groups, authSettings.OAuthGroups)
	}
	return isValidGroup
}

// isGrantedSession returns true if the user holds a valid internal session cookie
func isGrantedSession(w http.ResponseWriter, r *http.Request) (models.User, bool) {
	return sessionmanager.IsValidSession(w, r, authSettings.Method == models.AuthenticationOAuth2, authSettings.OAuthRecheckInterval)
}

// IsCorrectUsernameAndPassword checks if a provided username and password is correct
// Returns true if the user is authenticated, false otherwise
// Second return value is false if CSRF token is invalid, true otherwise
// Migrates legacy passwords to the new format
func IsCorrectUsernameAndPassword(username, password, userCsrfToken string) (models.User, bool, bool) {
	if !csrftoken.IsValid(csrftoken.TypeLogin, userCsrfToken) {
		return models.User{}, false, false
	}
	user, ok := database.GetUserByName(username)
	if !ok {
		return models.User{}, false, true
	}
	// Reject login if user has no password hash (OAuth-provisioned account)
	if user.Password == "" {
		return models.User{}, false, true
	}
	isSame, isLegacy := configuration.VerifyPassword(password, user.Password, configuration.Get().Authentication.SaltAdmin)
	if !isSame {
		return models.User{}, false, true
	}
	if isLegacy {
		user.Password = configuration.HashPassword(password, false, "")
		database.SaveUser(user, false)
	}
	return user, true, true
}

// Logout logs the user out and removes the session
func Logout(w http.ResponseWriter, r *http.Request) {
	isHybrid := authSettings.Method == models.AuthenticationInternal && authSettings.OAuthEnabledAlongsideInternal
	if authSettings.Method == models.AuthenticationInternal || authSettings.Method == models.AuthenticationOAuth2 || isHybrid {
		sessionmanager.LogoutSession(w, r)
	}
	if authSettings.Method == models.AuthenticationOAuth2 && !isHybrid {
		http.Redirect(w, r, "login?consent=true", http.StatusTemporaryRedirect)
	} else {
		http.Redirect(w, r, "login", http.StatusTemporaryRedirect)
	}
}

// IsLogoutAvailable returns true if a logout button should be shown with the current form of authentication
func IsLogoutAvailable() bool {
	return authSettings.Method == models.AuthenticationInternal || authSettings.Method == models.AuthenticationOAuth2
}
