package sessionmanager

import (
	"bytes"
	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/environment"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/test"
	"github.com/forceu/gokapi/internal/test/testconfiguration"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

var newSession string

func TestMain(m *testing.M) {
	testconfiguration.Create(false)
	configuration.Load()
	configuration.ConnectDatabase()
	exitVal := m.Run()
	testconfiguration.Delete()
	os.Exit(exitVal)
}

func getRecorder(cookies []test.Cookie) (*httptest.ResponseRecorder, *http.Request, bool, int) {
	w, r := test.GetRecorder("GET", "/", cookies, nil, nil)
	return w, r, false, 1
}

func TestIsValidSession(t *testing.T) {
	user, ok := IsValidSession(getRecorder(nil))
	test.IsEqualBool(t, ok, false)
	user, ok = IsValidSession(getRecorder([]test.Cookie{{
		Name:  "session_token",
		Value: "invalid"},
	}))
	test.IsEqualBool(t, ok, false)
	user, ok = IsValidSession(getRecorder([]test.Cookie{{
		Name:  "session_token",
		Value: ""},
	}))
	test.IsEqualBool(t, ok, false)
	user, ok = IsValidSession(getRecorder([]test.Cookie{{
		Name:  "session_token",
		Value: "expiredsession"},
	}))
	test.IsEqualBool(t, ok, false)
	user, ok = IsValidSession(getRecorder([]test.Cookie{{
		Name:  "session_token",
		Value: "validsession"},
	}))
	test.IsEqualBool(t, ok, true)
	_, ok = IsValidSession(getRecorder([]test.Cookie{{
		Name:  "session_token",
		Value: "validSessionInvalidUser"},
	}))
	test.IsEqualBool(t, ok, false)
	test.IsEqualInt(t, user.Id, 7)
	w, r, _, _ := getRecorder([]test.Cookie{{
		Name:  "session_token",
		Value: "needsRenewal"},
	})
	user, ok = IsValidSession(w, r, false, 1)
	cookies := w.Result().Cookies()
	test.IsEqualInt(t, len(cookies), 1)
	test.IsEqualString(t, cookies[0].Name, "session_token")
	session := cookies[0].Value
	test.IsEqualInt(t, len(session), 60)
	test.IsNotEqualString(t, session, "needsRenewal")
}

func TestCreateSession(t *testing.T) {
	w, _, _, _ := getRecorder(nil)
	CreateSession(w, false, 1, 5)
	cookies := w.Result().Cookies()
	test.IsEqualInt(t, len(cookies), 1)
	test.IsEqualString(t, cookies[0].Name, "session_token")
	newSession = cookies[0].Value
	test.IsEqualInt(t, len(newSession), 60)

	user, ok := IsValidSession(getRecorder([]test.Cookie{{
		Name:  "session_token",
		Value: newSession},
	}))
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, user.Id, 5)

	w, _, _, _ = getRecorder(nil)
	CreateSession(w, true, 20, 50)
	cookies = w.Result().Cookies()
	newOauthSession := cookies[0].Value

	var session models.Session
	session, ok = database.GetSession(newOauthSession)
	test.IsEqualBool(t, ok, true)
	isEqual := time.Now().Add(20*time.Hour).Unix()-session.ValidUntil < 10 &&
		time.Now().Add(20*time.Hour).Unix()-session.ValidUntil > -1
	test.IsEqualBool(t, isEqual, true)
}

// withServerUrl rewrites the on-disk test config so that ServerUrl uses the given
// scheme, reloads the configuration and returns a function that restores the
// original config. It does not touch the database, so session fixtures are unaffected.
func withServerUrl(t *testing.T, https bool) func() {
	configPath, _, _, _ := environment.GetConfigPaths()
	original, err := os.ReadFile(configPath)
	test.IsNil(t, err)

	modified := bytes.Replace(original, []byte(`"ServerUrl": "http://127.0.0.1:53843/"`), []byte(`"ServerUrl": "https://127.0.0.1:53843/"`), 1)
	if !https {
		modified = original
	}
	err = os.WriteFile(configPath, modified, 0777)
	test.IsNil(t, err)
	configuration.Load()

	return func() {
		err := os.WriteFile(configPath, original, 0777)
		test.IsNil(t, err)
		configuration.Load()
	}
}

func TestCookieSecureAttribute(t *testing.T) {
	test.IsEqualBool(t, configuration.UsesHttps(), false)
	w, _, _, _ := getRecorder(nil)
	CreateSession(w, false, 1, 5)
	cookies := w.Result().Cookies()
	test.IsEqualInt(t, len(cookies), 1)
	test.IsEqualBool(t, cookies[0].Secure, false)
	test.IsEqualBool(t, cookies[0].HttpOnly, true)
	test.IsEqual(t, cookies[0].SameSite, http.SameSiteLaxMode)

	w, r, _, _ := getRecorder(nil)
	LogoutSession(w, r)
	cookies = w.Result().Cookies()
	test.IsEqualInt(t, len(cookies), 1)
	test.IsEqualBool(t, cookies[0].Secure, false)

	restore := withServerUrl(t, true)
	defer restore()
	test.IsEqualBool(t, configuration.UsesHttps(), true)

	w, _, _, _ = getRecorder(nil)
	CreateSession(w, false, 1, 5)
	cookies = w.Result().Cookies()
	test.IsEqualInt(t, len(cookies), 1)
	test.IsEqualBool(t, cookies[0].Secure, true)
	test.IsEqualBool(t, cookies[0].HttpOnly, true)
	test.IsEqual(t, cookies[0].SameSite, http.SameSiteLaxMode)

	w, r, _, _ = getRecorder(nil)
	LogoutSession(w, r)
	cookies = w.Result().Cookies()
	test.IsEqualInt(t, len(cookies), 1)
	test.IsEqualBool(t, cookies[0].Secure, true)
}

func TestSessionDurationDays(t *testing.T) {
	w, _, _, _ := getRecorder(nil)
	CreateSession(w, false, 1, 5)
	cookies := w.Result().Cookies()
	session, ok := database.GetSession(cookies[0].Value)
	test.IsEqualBool(t, ok, true)
	isEqual := time.Now().Add(7*24*time.Hour).Unix()-session.ValidUntil < 10 &&
		time.Now().Add(7*24*time.Hour).Unix()-session.ValidUntil > -10
	test.IsEqualBool(t, isEqual, true)

	err := os.Setenv("GOKAPI_SESSION_DURATION_DAYS", "3")
	test.IsNil(t, err)
	defer os.Unsetenv("GOKAPI_SESSION_DURATION_DAYS")

	w, _, _, _ = getRecorder(nil)
	CreateSession(w, false, 1, 5)
	cookies = w.Result().Cookies()
	session, ok = database.GetSession(cookies[0].Value)
	test.IsEqualBool(t, ok, true)
	isEqual = time.Now().Add(3*24*time.Hour).Unix()-session.ValidUntil < 10 &&
		time.Now().Add(3*24*time.Hour).Unix()-session.ValidUntil > -10
	test.IsEqualBool(t, isEqual, true)

	// A session needing renewal should be renewed using the configured duration,
	// not left at its old expiry
	database.SaveSession("needsRenewalWithCustomDuration", models.Session{
		RenewAt:    0,
		ValidUntil: 2147483646,
		UserId:     7,
	})
	w, r, _, _ := getRecorder([]test.Cookie{{
		Name:  "session_token",
		Value: "needsRenewalWithCustomDuration"},
	})
	_, ok = IsValidSession(w, r, false, 1)
	test.IsEqualBool(t, ok, true)
	cookies = w.Result().Cookies()
	test.IsEqualInt(t, len(cookies), 1)
	renewedSession, ok := database.GetSession(cookies[0].Value)
	test.IsEqualBool(t, ok, true)
	isEqual = time.Now().Add(3*24*time.Hour).Unix()-renewedSession.ValidUntil < 10 &&
		time.Now().Add(3*24*time.Hour).Unix()-renewedSession.ValidUntil > -10
	test.IsEqualBool(t, isEqual, true)
}

// TestOAuthSessionNotLaunderedOnRenewal reproduces the hybrid-mode bug: isGrantedSession used to
// pass isOauth computed from the CURRENT global auth method (authSettings.Method ==
// AuthenticationOAuth2), which is always false in hybrid mode (Method stays
// AuthenticationInternal) even for a session the OAuth callback created with isOauth true. On
// renewal that recreated the session as a 7-day password session, so deprovisioning a user in
// Google would never end their session. The caller below deliberately passes isOauth=false, the
// exact value isGrantedSession would compute in hybrid mode, to prove renewal now reads
// session.IsOauth instead and keeps the OAuth recheck interval.
func TestOAuthSessionNotLaunderedOnRenewal(t *testing.T) {
	database.SaveSession("oauthNeedsRenewal", models.Session{
		RenewAt:    0,
		ValidUntil: 2147483646,
		UserId:     7,
		IsOauth:    true,
	})
	w, r, _, _ := getRecorder([]test.Cookie{{
		Name:  "session_token",
		Value: "oauthNeedsRenewal"},
	})
	_, ok := IsValidSession(w, r, false, 2)
	test.IsEqualBool(t, ok, true)
	cookies := w.Result().Cookies()
	test.IsEqualInt(t, len(cookies), 1)
	renewed, ok := database.GetSession(cookies[0].Value)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, renewed.IsOauth, true)
	// Renewed using the 2-hour OAuthRecheckInterval passed above, not the 7-day password
	// session default - otherwise the OAuth session was laundered into a long-lived one.
	isEqual := time.Now().Add(2*time.Hour).Unix()-renewed.ValidUntil < 10 &&
		time.Now().Add(2*time.Hour).Unix()-renewed.ValidUntil > -10
	test.IsEqualBool(t, isEqual, true)
}

func TestLogoutSession(t *testing.T) {
	user, ok := IsValidSession(getRecorder([]test.Cookie{{
		Name:  "session_token",
		Value: newSession},
	}))
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, user.Id, 5)
	w, r, _, _ := getRecorder([]test.Cookie{{
		Name:  "session_token",
		Value: newSession},
	})
	LogoutSession(w, r)
	_, ok = IsValidSession(getRecorder([]test.Cookie{{
		Name:  "session_token",
		Value: newSession},
	}))
	test.IsEqualBool(t, ok, false)
}
