package authentication

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/test"
	"github.com/forceu/gokapi/internal/test/testconfiguration"
	"github.com/forceu/gokapi/internal/webserver/authentication/csrftoken"
	"github.com/forceu/gokapi/internal/webserver/authentication/sessionmanager"
)

func TestMain(m *testing.M) {
	testconfiguration.Create(false)
	configuration.Load()
	configuration.ConnectDatabase()
	exitVal := m.Run()
	testconfiguration.Delete()
	os.Exit(exitVal)
}

func TestInit(t *testing.T) {
	Init(modelUserPW)
	test.IsEqualInt(t, authSettings.Method, models.AuthenticationInternal)
	test.IsEqualString(t, authSettings.Username, "test")
}

func TestIsValid(t *testing.T) {
	config := models.AuthenticationConfig{
		Method:    models.AuthenticationInternal,
		SaltAdmin: "1234",
		SaltFiles: "1234",
		Username:  "2s",
	}
	err := checkAuthConfig(config)
	test.IsNotNil(t, err)
	config.Username = "long name"
	err = checkAuthConfig(config)
	test.IsNil(t, err)

	config.Method = models.AuthenticationHeader
	err = checkAuthConfig(config)
	test.IsNotNil(t, err)
	config.HeaderKey = "header"
	err = checkAuthConfig(config)
	test.IsNil(t, err)

	config.Method = models.AuthenticationOAuth2
	err = checkAuthConfig(config)
	test.IsNotNil(t, err)
	config.OAuthProvider = "xxx"
	err = checkAuthConfig(config)
	test.IsNotNil(t, err)
	config.OAuthClientId = "xxx"
	err = checkAuthConfig(config)
	test.IsNotNil(t, err)
	config.OAuthClientSecret = "xxx"
	err = checkAuthConfig(config)
	test.IsNotNil(t, err)
	config.OAuthRecheckInterval = -1
	err = checkAuthConfig(config)
	test.IsNotNil(t, err)
	config.OAuthRecheckInterval = 1
	err = checkAuthConfig(config)
	test.IsNil(t, err)
}

func TestIsCorrectUsernameAndPassword(t *testing.T) {
	user, ok, csfrOk := IsCorrectUsernameAndPassword("test", "adminadmin", csrftoken.Generate(csrftoken.TypeLogin))
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, csfrOk, true)

	user, ok, csfrOk = IsCorrectUsernameAndPassword("Test", "adminadmin", csrftoken.Generate(csrftoken.TypeLogin))
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, csfrOk, true)
	test.IsEqualInt(t, user.Id, 5)
	user, ok, csfrOk = IsCorrectUsernameAndPassword("user", "useruser", csrftoken.Generate(csrftoken.TypeLogin))
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, csfrOk, true)
	test.IsEqualInt(t, user.Id, 7)
	_, ok, csfrOk = IsCorrectUsernameAndPassword("test", "wrong", csrftoken.Generate(csrftoken.TypeLogin))
	test.IsEqualBool(t, ok, false)
	test.IsEqualBool(t, csfrOk, true)
	_, ok, csfrOk = IsCorrectUsernameAndPassword("invalid", "adminadmin", csrftoken.Generate(csrftoken.TypeLogin))
	test.IsEqualBool(t, ok, false)
	test.IsEqualBool(t, csfrOk, true)
	_, ok, csfrOk = IsCorrectUsernameAndPassword("test", "adminadmin", "invalidToken")
	test.IsEqualBool(t, ok, false)
	test.IsEqualBool(t, csfrOk, false)
}

// TestIsCorrectUsernameAndPasswordRejectsNonInternalProvider is the reverse-direction guard for
// MAJOR W17-2a: before this fix, IsCorrectUsernameAndPassword only checked that the stored
// password hash was non-empty, never AuthProvider. So a Google-provisioned row that somehow
// obtained a password hash (e.g. an admin calling apiResetPassword on it before that path was
// closed) could authenticate through the internal password door, bypassing the IdP's MFA and
// deprovisioning entirely. This row has a hash that verifies against the correct password, so the
// only thing that can reject it is the AuthProvider check.
func TestIsCorrectUsernameAndPasswordRejectsNonInternalProvider(t *testing.T) {
	Init(modelUserPW)
	database.SaveUser(models.User{
		Id:           550,
		Name:         "googlepw@test.com",
		UserLevel:    models.UserLevelUser,
		AuthProvider: models.AuthProviderGoogle,
		Password:     configuration.HashPassword("correcthorsebattery", false, ""),
	}, false)

	_, ok, csfrOk := IsCorrectUsernameAndPassword("googlepw@test.com", "correcthorsebattery", csrftoken.Generate(csrftoken.TypeLogin))
	test.IsEqualBool(t, ok, false)
	test.IsEqualBool(t, csfrOk, true)
}

func TestIsAuthenticated(t *testing.T) {
	testAuthSession(t)
	testAuthHeader(t)
	testAuthDisabled(t)
	w, r := test.GetRecorder("GET", "/", nil, nil, nil)
	authSettings.Method = -1
	_, ok, _ := IsAuthenticated(w, r)
	test.IsEqualBool(t, ok, false)
}

func testAuthSession(t *testing.T) {

	exitCode := 0
	osExit = func(code int) {
		exitCode = code
	}

	w, r := test.GetRecorder("GET", "/", nil, nil, nil)
	Init(modelUserPW)
	_, ok, _ := IsAuthenticated(w, r)
	test.IsEqualBool(t, ok, false)
	Init(modelOauth)
	_, ok, _ = IsAuthenticated(w, r)
	test.IsEqualBool(t, ok, false)
	Init(modelUserPW)
	w, r = test.GetRecorder("GET", "/", []test.Cookie{{
		Name:  "session_token",
		Value: "validsession",
	}}, nil, nil)
	user, ok, _ := IsAuthenticated(w, r)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, user.Id, 7)
	test.IsEqualInt(t, exitCode, 0)

	Init(models.AuthenticationConfig{
		Method: 10,
	})
	test.IsEqualInt(t, exitCode, 3)

}

func testAuthHeader(t *testing.T) {
	w, r := test.GetRecorder("GET", "/", nil, nil, nil)
	Init(modelHeader)
	_, ok, err := IsAuthenticated(w, r)
	test.IsEqualBool(t, ok, false)
	test.IsNotNil(t, err)
	w, r = test.GetRecorder("GET", "/", nil, []test.Header{{
		Name:  "testHeader",
		Value: "testUser",
	}}, nil)

	user, ok, err := IsAuthenticated(w, r)
	test.IsEqualString(t, user.Name, "testuser")
	test.IsEqualBool(t, ok, true)
	test.IsNil(t, err)
	authSettings.OnlyRegisteredUsers = true
	w, r = test.GetRecorder("GET", "/", nil, []test.Header{{
		Name:  "testHeader",
		Value: "testUser",
	}}, nil)
	_, ok, err = IsAuthenticated(w, r)
	test.IsNil(t, err)
	test.IsEqualBool(t, ok, true)
	w, r = test.GetRecorder("GET", "/", nil, []test.Header{{
		Name:  "testHeader",
		Value: "otherUser2",
	}}, nil)
	_, ok, _ = IsAuthenticated(w, r)
	test.IsEqualBool(t, ok, false)
	authSettings.OnlyRegisteredUsers = false
}

func testAuthDisabled(t *testing.T) {
	w, r := test.GetRecorder("GET", "/", nil, nil, nil)
	Init(modelDisabled)
	user, ok, _ := IsAuthenticated(w, r)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, user.Id, 5)
}

func TestIsLogoutAvailable(t *testing.T) {
	authSettings.Method = models.AuthenticationInternal
	test.IsEqualBool(t, IsLogoutAvailable(), true)
	authSettings.Method = models.AuthenticationOAuth2
	test.IsEqualBool(t, IsLogoutAvailable(), true)
	authSettings.Method = models.AuthenticationHeader
	test.IsEqualBool(t, IsLogoutAvailable(), false)
	authSettings.Method = models.AuthenticationDisabled
	test.IsEqualBool(t, IsLogoutAvailable(), false)
}

func TestGetUserFromRequest(t *testing.T) {
	_, r := test.GetRecorder("GET", "/", nil, nil, nil)
	_, err := GetUserFromRequest(r)
	test.IsNotNil(t, err)
	c := context.WithValue(r.Context(), userNameContextKey, "invalid")
	rInvalid := r.WithContext(c)
	_, err = GetUserFromRequest(rInvalid)
	test.IsNotNil(t, err)

	user := models.User{
		Id:            1,
		Name:          "test",
		Permissions:   1,
		UserLevel:     2,
		LastOnline:    3,
		Password:      "12345",
		ResetPassword: true,
	}

	rValid := SetUserInRequest(r, user)
	retrievedUser, err := GetUserFromRequest(rValid)
	test.IsNil(t, err)
	test.IsEqual(t, retrievedUser, user)
}

func TestIsValidOauthUser(t *testing.T) {
	Init(modelOauth)
	info := OAuthUserInfo{Email: "", Subject: "randomid"}
	test.IsEqualBool(t, isValidOauthUser(info, []string{}), false)
	info.Email = "newemail"
	test.IsEqualBool(t, isValidOauthUser(info, []string{}), true)
	test.IsEqualBool(t, isValidOauthUser(info, []string{"test2"}), true)
	test.IsEqualBool(t, isValidOauthUser(info, []string{}), true)
	authSettings.OAuthGroupScope = "group"
	authSettings.OAuthGroups = []string{"othergroup"}
	info.Email = "test1"
	test.IsEqualBool(t, isValidOauthUser(info, []string{}), false)
	info.Email = "otheruser"
	test.IsEqualBool(t, isValidOauthUser(info, []string{}), false)
	info.Email = "test1"
	test.IsEqualBool(t, isValidOauthUser(info, []string{"testgroup"}), false)
	test.IsEqualBool(t, isValidOauthUser(info, []string{"testgroup", "othergroup"}), true)
	info.Email = "otheruser"
	test.IsEqualBool(t, isValidOauthUser(info, []string{"othergroup"}), true)
	test.IsEqualBool(t, isValidOauthUser(info, []string{"testgroup", "othergroup"}), true)
	info.Subject = ""
	test.IsEqualBool(t, isValidOauthUser(info, []string{"testgroup", "othergroup"}), false)
}

// TestGetOrCreateUserAllowList covers what the OIDC door does and does not accept. Being in the
// user list is the allow-list: any account an admin added may sign in through SSO, whatever its
// AuthProvider, including the empty value every pre-2.x row carries. What is enforced is
// identity continuity - the OIDC subject binds on first use and must match exactly afterwards -
// and OnlyRegisteredUsers, which keeps an unknown address from creating an account.
func TestGetOrCreateUserAllowList(t *testing.T) {
	Init(modelOauth)

	// Accepted: a pre-existing row with no AuthProvider set at all.
	database.SaveUser(models.User{Name: "blankprovider@test.com", UserLevel: models.UserLevelUser, AuthProvider: ""}, true)
	blankUser, ok, err := getOrCreateUser("blankprovider@test.com", models.AuthProviderGoogle, "sub-blank")
	test.IsNil(t, err)
	test.IsEqualBool(t, ok, true)
	boundBlank, found := database.GetUserByName("blankprovider@test.com")
	test.IsEqualBool(t, found, true)
	test.IsEqualString(t, boundBlank.OidcSubject, "sub-blank")
	test.IsEqualInt(t, blankUser.Id, boundBlank.Id)

	// Accepted: an ordinary password account, added by an admin, signing in with SSO for the
	// first time. This is the common case - an account is not provisioned per door.
	database.SaveUser(models.User{Name: "internalprovider@test.com", UserLevel: models.UserLevelSuperAdmin, AuthProvider: models.AuthProviderInternal}, true)
	_, ok, err = getOrCreateUser("internalprovider@test.com", models.AuthProviderGoogle, "sub-internal")
	test.IsNil(t, err)
	test.IsEqualBool(t, ok, true)

	// Rejected: that same account, now presenting a different subject.
	_, ok, err = getOrCreateUser("internalprovider@test.com", models.AuthProviderGoogle, "sub-internal-other")
	test.IsEqualBool(t, errors.Is(err, errTakeoverRejected), true)
	test.IsEqualBool(t, ok, false)

	database.SaveUser(models.User{Name: "googleprovider@test.com", UserLevel: models.UserLevelUser, AuthProvider: models.AuthProviderGoogle}, true)

	// Accepted: row provisioned for Google, no subject bound yet - binds on first use.
	user, ok, err := getOrCreateUser("googleprovider@test.com", models.AuthProviderGoogle, "sub-google")
	test.IsNil(t, err)
	test.IsEqualBool(t, ok, true)
	boundUser, found := database.GetUserByName("googleprovider@test.com")
	test.IsEqualBool(t, found, true)
	test.IsEqualString(t, boundUser.OidcSubject, "sub-google")
	test.IsEqualInt(t, user.Id, boundUser.Id)

	// Accepted: same row, same subject presented again (ordinary repeat login).
	_, ok, err = getOrCreateUser("googleprovider@test.com", models.AuthProviderGoogle, "sub-google")
	test.IsNil(t, err)
	test.IsEqualBool(t, ok, true)

	// Rejected: same email, a DIFFERENT subject now presented - e.g. a corporate mailbox
	// reassigned to someone else in Google - must not inherit the previous owner's account.
	_, ok, err = getOrCreateUser("googleprovider@test.com", models.AuthProviderGoogle, "sub-different")
	test.IsEqualBool(t, errors.Is(err, errTakeoverRejected), true)
	test.IsEqualBool(t, ok, false)

	// Auto-provisioning of a brand-new email must be refused once OnlyRegisteredUsers is true.
	authSettings.OnlyRegisteredUsers = true
	_, ok, err = getOrCreateUser("nevercreated@test.com", models.AuthProviderGoogle, "sub-new")
	test.IsNil(t, err)
	test.IsEqualBool(t, ok, false)
	_, found = database.GetUserByName("nevercreated@test.com")
	test.IsEqualBool(t, found, false)
	authSettings.OnlyRegisteredUsers = false
}

// TestGetOrCreateUserRejectsGoogleProvisionedThroughHeaderDoor verifies MINOR-7: the header-auth
// door (isGrantedHeader always calls getOrCreateUser with provider == models.AuthProviderInternal)
// must not authenticate a row that was deliberately provisioned for Google, just because a
// reverse proxy presents a matching username. Before this fix, the allow-list check only ran when
// provider == models.AuthProviderGoogle, so a google-provisioned row sailed straight through the
// `return user, true, nil` at the end unchecked when called with the internal provider - the
// reverse of the account-takeover gap TestGetOrCreateUserAllowList already covers for the OAuth
// door.
func TestGetOrCreateUserRejectsGoogleProvisionedThroughHeaderDoor(t *testing.T) {
	Init(modelHeader)

	database.SaveUser(models.User{Name: "headerdoorgoogle@test.com", UserLevel: models.UserLevelUser, AuthProvider: models.AuthProviderGoogle}, true)

	_, ok, err := getOrCreateUser("headerdoorgoogle@test.com", models.AuthProviderInternal, "")
	test.IsEqualBool(t, errors.Is(err, errTakeoverRejected), true)
	test.IsEqualBool(t, ok, false)

	// An ordinary internal-auth row must still authenticate through the header door.
	database.SaveUser(models.User{Name: "headerdoorinternal@test.com", UserLevel: models.UserLevelUser, AuthProvider: models.AuthProviderInternal}, true)
	user, ok, err := getOrCreateUser("headerdoorinternal@test.com", models.AuthProviderInternal, "")
	test.IsNil(t, err)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, user.Name, "headerdoorinternal@test.com")
}

// TestGoogleProvisionedUserOidcSucceedsPasswordRejected ties together W17-1 and W17-2a: a user
// deliberately provisioned with the google AuthProvider (as an admin now can via the
// authprovider header on /user/create, see users.Create) must authenticate successfully through
// the OIDC path (getOrCreateUser) while being rejected outright through the password path
// (IsCorrectUsernameAndPassword), even if the row somehow carries a password hash.
func TestGoogleProvisionedUserOidcSucceedsPasswordRejected(t *testing.T) {
	Init(modelOauth)
	database.SaveUser(models.User{
		Id:           560,
		Name:         "provisioned@test.com",
		UserLevel:    models.UserLevelUser,
		AuthProvider: models.AuthProviderGoogle,
		Password:     configuration.HashPassword("shouldnevermatter", false, ""),
	}, false)

	// OIDC path succeeds and binds the subject.
	user, ok, err := getOrCreateUser("provisioned@test.com", models.AuthProviderGoogle, "sub-provisioned")
	test.IsNil(t, err)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, user.Id, 560)

	// Password path is rejected outright, even with the password that matches the stored hash.
	Init(modelUserPW)
	_, ok, csfrOk := IsCorrectUsernameAndPassword("provisioned@test.com", "shouldnevermatter", csrftoken.Generate(csrftoken.TypeLogin))
	test.IsEqualBool(t, ok, false)
	test.IsEqualBool(t, csfrOk, true)
}

func TestWildcardMatch(t *testing.T) {
	type testPattern struct {
		Pattern string
		Input   string
		Result  bool
	}
	tests := []testPattern{{
		Pattern: "test",
		Input:   "test",
		Result:  true,
	}, {
		Pattern: "test*",
		Input:   "test",
		Result:  true,
	}, {
		Pattern: "*test",
		Input:   "test",
		Result:  true,
	}, {
		Pattern: "te*st",
		Input:   "test",
		Result:  true,
	}, {
		Pattern: "test*",
		Input:   "1test",
		Result:  false,
	}, {
		Pattern: "*test",
		Input:   "test1",
		Result:  false,
	}, {
		Pattern: "te*st",
		Input:   "teeeeeeeest",
		Result:  true,
	}, {
		Pattern: "te*st",
		Input:   "teast",
		Result:  true,
	}, {
		Pattern: "te*st",
		Input:   "te@st",
		Result:  true,
	}, {
		Pattern: "*@github.com",
		Input:   "email@github.com",
		Result:  true,
	}, {
		Pattern: "@github.com",
		Input:   "email@github.com",
		Result:  false,
	}, {
		Pattern: "@github.com",
		Input:   "email@gokapi.com",
		Result:  false,
	}, {
		Pattern: "*@github.com",
		Input:   "email@gokapi.com",
		Result:  false,
	}}
	for _, patternTest := range tests {
		fmt.Printf("Testing: %s == %s, expecting %v\n", patternTest.Pattern, patternTest.Input, patternTest.Result)
		result, err := matchesWithWildcard(patternTest.Pattern, patternTest.Input)
		test.IsNil(t, err)
		test.IsEqualBool(t, result, patternTest.Result)
	}
}

func getRecorder(cookies []test.Cookie) (*httptest.ResponseRecorder, *http.Request) {
	w, r := test.GetRecorder("GET", "/", cookies, nil, nil)
	return w, r
}

func TestLogout(t *testing.T) {
	Init(modelUserPW)
	w, r := getRecorder([]test.Cookie{{
		Name:  "session_token",
		Value: "logoutsession"},
	})
	_, ok := sessionmanager.IsValidSession(w, r, 0)
	test.IsEqualBool(t, ok, true)
	Logout(w, r)
	_, ok = database.GetSession("logoutsession")
	test.IsEqualBool(t, ok, false)
	_, ok = sessionmanager.IsValidSession(w, r, 0)
	test.IsEqualBool(t, ok, false)
	test.ResponseIsRedirect(t, w, "login", false)

	Init(modelOauth)
	w, r = getRecorder([]test.Cookie{{
		Name:  "session_token",
		Value: "logoutsession2"},
	})
	_, ok = sessionmanager.IsValidSession(w, r, 0)
	test.IsEqualBool(t, ok, true)
	Logout(w, r)
	_, ok = database.GetSession("logoutsession")
	test.IsEqualBool(t, ok, false)
	_, ok = sessionmanager.IsValidSession(w, r, 0)
	test.IsEqualBool(t, ok, false)
	test.ResponseIsRedirect(t, w, "login?consent=true", false)
}

// TestLogoutHybridForcesConsentForOauthSession reproduces the hybrid-mode logout bug: consent
// was only forced when Method == AuthenticationOAuth2 && !isHybrid, so hybrid mode never forced
// it - not even for a session the OAuth callback itself created. On a shared workstation, logout
// therefore did not visibly end the session: the next /oauth-login used prompt=none and silently
// reauthenticated. A hybrid session that was NOT created by OAuth must still log out plainly.
func TestLogoutHybridForcesConsentForOauthSession(t *testing.T) {
	modelHybrid := models.AuthenticationConfig{
		Method:                        models.AuthenticationInternal,
		SaltAdmin:                     testconfiguration.SaltAdmin,
		SaltFiles:                     "1234",
		Username:                      "test",
		OAuthEnabledAlongsideInternal: true,
		OAuthProvider:                 "test",
		OAuthClientId:                 "test",
		OAuthClientSecret:             "test",
		OAuthRecheckInterval:          1,
	}
	Init(modelHybrid)

	database.SaveSession("hybridOauthSession", models.Session{
		RenewAt:    2147483645,
		ValidUntil: 2147483646,
		UserId:     7,
		IsOauth:    true,
	})
	w, r := getRecorder([]test.Cookie{{
		Name:  "session_token",
		Value: "hybridOauthSession"},
	})
	Logout(w, r)
	test.ResponseIsRedirect(t, w, "login?consent=true", false)

	database.SaveSession("hybridPasswordSession", models.Session{
		RenewAt:    2147483645,
		ValidUntil: 2147483646,
		UserId:     7,
		IsOauth:    false,
	})
	w, r = getRecorder([]test.Cookie{{
		Name:  "session_token",
		Value: "hybridPasswordSession"},
	})
	Logout(w, r)
	test.ResponseIsRedirect(t, w, "login", false)
}

type testInfo struct {
	Output []byte
}

func (t testInfo) Claims(v interface{}) error {
	if t.Output == nil {
		return errors.New("oidc: claims not set")
	}
	return json.Unmarshal(t.Output, v)
}
func getOauthUserOutput(t *testing.T, info OAuthUserInfo) (*httptest.ResponseRecorder, error) {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	err := CheckOauthUserAndRedirect(w, r, info)
	if err != nil {
		return w, err
	}
	return w, nil
}
func TestCheckOauthUser(t *testing.T) {
	Init(modelOauth)
	info := OAuthUserInfo{
		ClaimsSent: testInfo{Output: []byte(`{"amr":["pwd","hwk","user","pin","mfa"],"aud":["gokapi-dev"],"auth_time":1705573822,"azp":"gokapi-dev","client_id":"gokapi-dev","email":"test@test.com","email_verified":true,"groups":["admins","dev"],"iat":1705577400,"iss":"https://auth.test.com","name":"gokapi","preferred_username":"gokapi","rat":1705577400,"sub":"944444cf3e-0546-44f2-acfa-a94444444360"}`)},
	}
	w, err := getOauthUserOutput(t, info)
	test.IsNil(t, err)
	test.ResponseIsRedirect(t, w, "error", true)

	info.Subject = "random"
	w, err = getOauthUserOutput(t, info)
	test.IsNil(t, err)
	test.ResponseIsRedirect(t, w, "error", true)

	info.Email = "random"
	w, err = getOauthUserOutput(t, info)
	test.IsNil(t, err)
	test.ResponseIsRedirect(t, w, "/", false)

	info.Email = "test@test-invalid.com"
	authSettings.OnlyRegisteredUsers = true
	w, err = getOauthUserOutput(t, info)
	test.IsNil(t, err)
	test.ResponseIsRedirect(t, w, "error", true)

	info.Email = "random"
	w, err = getOauthUserOutput(t, info)
	test.IsNil(t, err)
	test.ResponseIsRedirect(t, w, "/", false)

	authSettings.OnlyRegisteredUsers = false
	authSettings.OAuthGroups = []string{"otheruser@test"}
	authSettings.OAuthGroupScope = "groupscope"
	newClaims := testInfo{Output: []byte("{invalid")}
	info.ClaimsSent = newClaims
	_, err = getOauthUserOutput(t, info)
	test.IsNotNil(t, err)
}

var modelUserPW = models.AuthenticationConfig{
	Method:    models.AuthenticationInternal,
	SaltAdmin: testconfiguration.SaltAdmin,
	SaltFiles: "1234",
	Username:  "test",
}
var modelOauth = models.AuthenticationConfig{
	Method:               models.AuthenticationOAuth2,
	SaltAdmin:            testconfiguration.SaltAdmin,
	SaltFiles:            "1234",
	OAuthProvider:        "test",
	OAuthClientId:        "test",
	OAuthClientSecret:    "test",
	OAuthRecheckInterval: 1,
}
var modelHeader = models.AuthenticationConfig{
	Method:    models.AuthenticationHeader,
	SaltAdmin: testconfiguration.SaltAdmin,
	SaltFiles: "1234",
	HeaderKey: "testHeader",
}
var modelDisabled = models.AuthenticationConfig{
	Method:    models.AuthenticationDisabled,
	SaltAdmin: testconfiguration.SaltAdmin,
	SaltFiles: "1234",
}
