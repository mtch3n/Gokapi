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
	"github.com/forceu/gokapi/internal/webserver/authentication/avatar"
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
	Subject string
	Email   string
	// PictureUrl is the provider's "picture" claim, empty when the provider sends none. It is
	// never handed to the browser: the image is fetched and cached server-side, see the avatar
	// package.
	PictureUrl string
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
		if errCreate != nil && !errors.Is(errCreate, errTakeoverRejected) {
			return errCreate
		}
		if ok {
			sessionmanager.CreateSession(w, true, authSettings.OAuthRecheckInterval, user.Id)
			avatar.StoreAsync(user.Id, userInfo.PictureUrl)
			logging.LogValidLogin(userInfo.Email, userInfo.Subject, logging.GetIpAddress(r))
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return nil
		}
		if errors.Is(errCreate, errTakeoverRejected) {
			// Distinct from an ordinary failed login: a Google login was presented for an
			// account that was not provisioned for OAuth (or whose OIDC subject no longer
			// matches), i.e. a rejected account-takeover attempt rather than a wrong password.
			logging.LogOauthTakeoverRejected(userInfo.Email, logging.GetIpAddress(r))
			errorHandling.RedirectGenericErrorPage(w, r, errorHandling.TypeOAuthNotAuthorised)
			return nil
		}
	}
	logging.LogInvalidLogin(userInfo.Email, logging.GetIpAddress(r))
	errorHandling.RedirectGenericErrorPage(w, r, errorHandling.TypeOAuthNotAuthorised)
	return nil
}

// getOrCreateUser handles provider-aware user binding.
//
// For OAuth/OIDC (provider == models.AuthProviderGoogle): any account an admin has added may
// sign in through SSO. There is no per-account opt-in, because an account is added by an admin
// in the first place - being in the user list IS the allow-list, and OnlyRegisteredUsers keeps
// an unknown email address from creating one. What is still enforced is identity continuity:
// the OIDC subject is bound to the row on the first SSO login and must match exactly on every
// later one, so a corporate mailbox reassigned to a different person in the provider cannot
// inherit the previous owner's account.
//
// Note that this means a verified email address at the provider is trusted to identify the
// account of the same name. That is sound when the provider is a directory the operator
// controls (a Google Workspace domain only ever issues its own identities, and
// checkEmailVerified rejects an unverified address), and it is why OAuthGroups exists for
// narrowing further.
//
// For internal/header auth: matches by username only. A row deliberately provisioned for Google
// through the authprovider header on user/create is still refused here, since the header door is
// not an OIDC subject check and nothing else would catch it.
//
// errTakeoverRejected is returned (never as a hard failure the caller propagates as an HTTP
// error - CheckOauthUserAndRedirect treats it the same as any other "not authorized" outcome)
// specifically so the caller can log the rejection distinctly from an ordinary failed login, see
// logging.LogOauthTakeoverRejected.
var errTakeoverRejected = errors.New("oauth login rejected: the presented identity does not match the account")

func getOrCreateUser(username, provider, oidcSubject string) (models.User, bool, error) {
	user, ok := database.GetUserByName(username)
	if ok {
		if provider == models.AuthProviderGoogle {
			if user.OidcSubject == "" {
				// First SSO login for this account: bind the subject that will identify it
				// from now on.
				user.OidcSubject = oidcSubject
				database.SaveUser(user, false)
			} else if user.OidcSubject != oidcSubject {
				// A different subject is presented for the same email - e.g. a reassigned
				// corporate mailbox - must not inherit the previous owner's account.
				return models.User{}, false, errTakeoverRejected
			}
		} else if user.AuthProvider != provider {
			// The reverse of the OAuth allow-list above: this is the header-auth door
			// (provider == models.AuthProviderInternal, the only other caller of
			// getOrCreateUser). A row deliberately provisioned for Google (e.g. via the
			// authprovider header on user/create) must not authenticate through the reverse
			// proxy header door just because the header presents a matching username - the
			// header door is not an OIDC subject check, so nothing else here would catch it.
			return models.User{}, false, errTakeoverRejected
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

// checkEmailVerified extracts and validates the email_verified claim.
// An absent claim is treated as verified only for a Google issuer, which always sends this
// claim in practice, so absence should not occur there. For every other OIDC issuer, the claim
// is optional per spec, so a provider that omits it is treated as UNVERIFIED rather than
// silently trusted - and the omission is logged distinctly so it does not read as a wrong
// password or a rejected takeover attempt in the log.
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

	emailVerified, exists := data["email_verified"]
	if !exists {
		if isGoogleProvider() {
			return nil
		}
		log.Println("oauth: email_verified claim absent for a non-Google issuer, treating login as unverified")
		return errors.New("email_verified claim is missing")
	}
	verified, ok := emailVerified.(bool)
	if !ok {
		return errors.New("email_verified claim is not a boolean")
	}
	if !verified {
		return errors.New("email_verified claim is false")
	}
	return nil
}

// isGoogleProvider returns true if the configured OIDC provider is Google.
func isGoogleProvider() bool {
	return strings.Contains(authSettings.OAuthProvider, "accounts.google.com")
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
	return sessionmanager.IsValidSession(w, r, authSettings.OAuthRecheckInterval)
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
	// Reject login for any user not provisioned for internal auth. This is the allow-list
	// counterpart to getOrCreateUser's OAuth allow-list: a row provisioned for Google/OIDC
	// must never authenticate through the password door, even if it somehow ended up with a
	// non-empty password hash (e.g. an admin calling apiResetPassword on it before that path
	// was closed). Checked before the password hash so the reason is unambiguous.
	if user.AuthProvider != models.AuthProviderInternal {
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
	wasOauthSession := false
	if authSettings.Method == models.AuthenticationInternal || authSettings.Method == models.AuthenticationOAuth2 || isHybrid {
		wasOauthSession = sessionmanager.LogoutSession(w, r)
	}
	// Force re-consent whenever the session just logged out was itself created by the OAuth
	// callback (models.Session.IsOauth), in addition to the pre-existing unconditional case for
	// plain OAuth2 mode. Before this, hybrid mode never forced consent - even for a session the
	// OAuth callback created - so on a shared workstation, logout did not visibly end the
	// session: the next /oauth-login used prompt=none and silently reauthenticated.
	if (authSettings.Method == models.AuthenticationOAuth2 && !isHybrid) || wasOauthSession {
		http.Redirect(w, r, "login?consent=true", http.StatusTemporaryRedirect)
	} else {
		http.Redirect(w, r, "login", http.StatusTemporaryRedirect)
	}
}

// IsLogoutAvailable returns true if a logout button should be shown with the current form of authentication
func IsLogoutAvailable() bool {
	return authSettings.Method == models.AuthenticationInternal || authSettings.Method == models.AuthenticationOAuth2
}
