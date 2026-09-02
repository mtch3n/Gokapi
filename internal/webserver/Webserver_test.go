//go:build !integration && test

package webserver

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/helper"
	gokapimail "github.com/forceu/gokapi/internal/mail"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/shareaccess"
	"github.com/forceu/gokapi/internal/storage/filebundle"
	"github.com/forceu/gokapi/internal/storage/processingstatus"
	"github.com/forceu/gokapi/internal/test"
	"github.com/forceu/gokapi/internal/test/testconfiguration"
	"github.com/forceu/gokapi/internal/webserver/authentication"
	"github.com/forceu/gokapi/internal/webserver/authentication/csrftoken"
	"github.com/forceu/gokapi/internal/webserver/authentication/oauth"
	"github.com/forceu/gokapi/internal/webserver/ratelimiter"
)

func TestMain(m *testing.M) {
	testconfiguration.Create(true)
	configuration.Load()
	configuration.ConnectDatabase()
	authentication.Init(configuration.Get().Authentication)
	go Start()
	time.Sleep(1 * time.Second)
	ratelimiter.SetUnitTestMode(true)
	exitVal := m.Run()
	testconfiguration.Delete()
	os.Exit(exitVal)
}

func TestEmbedFs(t *testing.T) {
	funcMap := template.FuncMap{
		"newAdminButtonContext": newAdminButtonContext,
	}
	templates, err := template.New("").Funcs(funcMap).ParseFS(templateFolderEmbedded, "web/templates/*.tmpl")
	if err != nil {
		t.Error("Unable to read templates")
		return
	}
	if !strings.Contains(templates.DefinedTemplates(), "header") {
		t.Error("Unable to parse templates")
	}
}

func TestIndexRedirect(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://localhost:53843/",
		RequiredContent: []string{"<html><head><meta http-equiv=\"Refresh\" content=\"0; URL=./index\"></head></html>"},
		IsHtml:          true,
	})
}
func TestIndexFile(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://localhost:53843/index",
		RequiredContent: []string{configuration.Get().RedirectUrl},
		IsHtml:          true,
	})
}
func TestStaticDirs(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://localhost:53843/css/cover.css",
		RequiredContent: []string{".btn-secondary:hover"},
	})
}

func postValues(username, password, csrf string) []test.PostBody {
	return []test.PostBody{
		{Key: "username", Value: username},
		{Key: "password", Value: password},
		{Key: "csrf-token", Value: csrf},
	}
}

func cookieValue(cookies []*http.Cookie, name string) string {
	for _, c := range cookies {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

func TestLogin(t *testing.T) {
	const loginUrl = "http://localhost:53843/login"

	// GET /login shows the login form
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             loginUrl,
		IsHtml:          true,
		ResultCode:      http.StatusOK,
		RequiredContent: []string{"id=\"uname_hidden\""},
	})

	postConfig := test.HttpTestConfig{
		Url:             loginUrl,
		IsHtml:          true,
		Method:          "POST",
		ResultCode:      http.StatusOK,
		RequiredContent: []string{"id=\"uname_hidden\"", "Incorrect username or password"},
		ExcludedContent: []string{"URL=./admin"},
	}

	// POST with wrong username and password shows error
	postConfig.PostValues = postValues("invalid", "invalid", csrftoken.Generate(csrftoken.TypeLogin))
	test.HttpPostRequest(t, postConfig)

	// POST with correct username but wrong password shows error
	postConfig.PostValues = postValues("test", "invalid", csrftoken.Generate(csrftoken.TypeLogin))
	test.HttpPostRequest(t, postConfig)

	// POST with correct credentials but invalid CSRF token shows error
	postConfig.PostValues = postValues("test", "adminadmin", "invalid")
	postConfig.RequiredContent = []string{"id=\"uname_hidden\"", "The login page was open too long and expired. Please try again."}
	test.HttpPostRequest(t, postConfig)

	// GET /login with OAuth2 enabled redirects to oauth-login
	oauthConfig := configuration.Get()
	oauthConfig.Authentication.Method = models.AuthenticationOAuth2
	oauthConfig.Authentication.OAuthProvider = "http://test.com"
	oauthConfig.Authentication.OAuthClientSecret = "secret"
	oauthConfig.Authentication.OAuthClientId = "client"
	authentication.Init(oauthConfig.Authentication)
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:         loginUrl,
		ResultCode:  http.StatusTemporaryRedirect,
		RedirectUrl: "oauth-login",
	})
	configuration.Get().Authentication.Method = models.AuthenticationInternal
	authentication.Init(configuration.Get().Authentication)

	// POST with valid credentials returns a redirect to admin and sets a session cookie
	postConfig.RequiredContent = nil
	postConfig.ExcludedContent = nil
	postConfig.IsHtml = false
	postConfig.ResultCode = http.StatusTemporaryRedirect
	postConfig.RedirectUrl = "admin"
	postConfig.PostValues = postValues("test", "adminadmin", csrftoken.Generate(csrftoken.TypeLogin))
	cookies := test.HttpPostRequest(t, postConfig)
	session := cookieValue(cookies, "session_token")
	test.IsNotEqualString(t, session, "")

	// Visiting /login with a valid session redirects to admin
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:         loginUrl,
		ResultCode:  http.StatusTemporaryRedirect,
		RedirectUrl: "admin",
		Cookies:     []test.Cookie{{Name: "session_token", Value: session}},
	})
}

// TestShowLoginSetsForceConsentCookieInHybridMode verifies BLOCKER W17-3a: logout redirects to
// login?consent=true for an OAuth session, but in hybrid mode showLogin does not take the
// oauth-login redirect branch (it shows the login choice page instead), so that query parameter
// used to simply be dropped - the SPA's own "Sign in with Google" button navigated to
// /oauth-login with no query string, and oauth.HandlerLogin silently reauthenticated the
// previous session's account. showLogin must now set a short-lived cookie that makes the next
// call to oauth.HandlerLogin force consent independently of any query string being forwarded.
func TestShowLoginSetsForceConsentCookieInHybridMode(t *testing.T) {
	config := configuration.Get()
	originalMethod := config.Authentication.Method
	originalHybrid := config.Authentication.OAuthEnabledAlongsideInternal
	config.Authentication.Method = models.AuthenticationInternal
	config.Authentication.OAuthEnabledAlongsideInternal = true
	defer func() {
		config.Authentication.Method = originalMethod
		config.Authentication.OAuthEnabledAlongsideInternal = originalHybrid
	}()

	w := httptest.NewRecorder()
	showLogin(w, httptest.NewRequest("GET", "/login?consent=true", nil))
	var foundConsentCookie bool
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == oauth.CookieForceConsent && cookie.Value == "true" {
			foundConsentCookie = true
		}
	}
	test.IsEqualBool(t, foundConsentCookie, true)

	w2 := httptest.NewRecorder()
	showLogin(w2, httptest.NewRequest("GET", "/login", nil))
	for _, cookie := range w2.Result().Cookies() {
		test.IsEqualBool(t, cookie.Name == oauth.CookieForceConsent, false)
	}
}

// TestAdminHybridResetPasswordGate verifies MAJOR-3 W17-2c: the guard in requireLogin that
// forces a logged-in user into the changePassword flow. Before this fix, the condition was
// authConfig.Method == models.AuthenticationInternal || (isHybrid && ...) - but isHybrid already
// implies Method == AuthenticationInternal, so the first disjunct made the whole condition true
// whenever isHybrid was true regardless of AuthProvider, and a Google-provisioned user in hybrid
// mode with ResetPassword true was wrongly redirected into changePassword. An internal user with
// ResetPassword true in the same hybrid config must still be redirected, so the fix is scoped to
// AuthProvider and not an accidental blanket exemption.
func TestAdminHybridResetPasswordGate(t *testing.T) {
	const idGoogleUser = 601
	const idInternalUser = 602

	database.SaveUser(models.User{
		Id:            idGoogleUser,
		Name:          "hybridgoogleuser@test.com",
		UserLevel:     models.UserLevelUser,
		AuthProvider:  models.AuthProviderGoogle,
		ResetPassword: true,
	}, false)
	database.SaveSession("hybridGoogleSession", models.Session{
		RenewAt:    2147483645,
		ValidUntil: 2147483646,
		UserId:     idGoogleUser,
	})

	database.SaveUser(models.User{
		Id:            idInternalUser,
		Name:          "hybridinternaluser@test.com",
		UserLevel:     models.UserLevelUser,
		AuthProvider:  models.AuthProviderInternal,
		Password:      "somehash",
		ResetPassword: true,
	}, false)
	database.SaveSession("hybridInternalSession", models.Session{
		RenewAt:    2147483645,
		ValidUntil: 2147483646,
		UserId:     idInternalUser,
	})

	config := configuration.Get()
	config.Authentication.Method = models.AuthenticationInternal
	config.Authentication.OAuthEnabledAlongsideInternal = true
	config.Authentication.OAuthProvider = "http://test.com"
	config.Authentication.OAuthClientId = "client"
	config.Authentication.OAuthClientSecret = "secret"
	config.Authentication.OAuthRecheckInterval = 1
	authentication.Init(config.Authentication)

	// A Google-provisioned user must not be forced into changePassword in hybrid mode.
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://localhost:53843/admin",
		RequiredContent: []string{"Downloads remaining"},
		ExcludedContent: []string{"Change Password"},
		IsHtml:          true,
		Cookies: []test.Cookie{{
			Name:  "session_token",
			Value: "hybridGoogleSession",
		}},
	})

	// An internal user with ResetPassword must still be redirected in the same hybrid config.
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:         "http://localhost:53843/admin",
		RedirectUrl: "changePassword",
		Cookies: []test.Cookie{{
			Name:  "session_token",
			Value: "hybridInternalSession",
		}},
	})

	configuration.Get().Authentication.Method = models.AuthenticationInternal
	configuration.Get().Authentication.OAuthEnabledAlongsideInternal = false
	authentication.Init(configuration.Get().Authentication)
}

func TestAdminNoAuth(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:         "http://localhost:53843/admin",
		RedirectUrl: "login",
	})
}
func TestAdminAuth(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://localhost:53843/admin",
		RequiredContent: []string{"Downloads remaining"},
		IsHtml:          true,
		Cookies: []test.Cookie{{
			Name:  "session_token",
			Value: "validsession",
		}},
	})
}
func TestAdminExpiredAuth(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:         "http://localhost:53843/admin",
		RedirectUrl: "login",
		Cookies: []test.Cookie{{
			Name:  "session_token",
			Value: "expiredsession",
		}},
	})
}

func TestAdminRenewalAuth(t *testing.T) {
	t.Parallel()
	cookies := test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://localhost:53843/admin",
		RequiredContent: []string{"Downloads remaining"},
		IsHtml:          true,
		Cookies: []test.Cookie{{
			Name:  "session_token",
			Value: "needsRenewal",
		}},
	})
	sessionCookie := "needsRenewal"
	for _, cookie := range cookies {
		if (*cookie).Name == "session_token" {
			sessionCookie = (*cookie).Value
			break
		}
	}
	if sessionCookie == "needsRenewal" {
		t.Error("Session not renewed")
	}
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://localhost:53843/admin",
		RequiredContent: []string{"Downloads remaining"},
		IsHtml:          true,
		Cookies: []test.Cookie{{
			Name:  "session_token",
			Value: sessionCookie,
		}},
	})
}

func TestAdminInvalidAuth(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:         "http://localhost:53843/admin",
		RedirectUrl: "login",
		Cookies: []test.Cookie{{
			Name:  "session_token",
			Value: "invalid",
		}},
	})
}

func TestInvalidLink(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:                "http://localhost:53843/d?id=123",
		IgnoreRedirectParm: true,
		RedirectUrl:        "error",
	})
}

// TestInvalidLinkIsAudited is a W7 coverage test: an unknown-id probe against a public download
// link (the most common denial case, and one PLAN.md explicitly calls out as an enumeration
// signal worth recording) must produce a "denied" audit entry, not just the redirect.
func TestInvalidLinkIsAudited(t *testing.T) {
	t.Parallel()
	const unknownId = "doesNotExistW7auditCoverageTest"
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:                "http://localhost:53843/d?id=" + unknownId,
		IgnoreRedirectParm: true,
		RedirectUrl:        "error",
	})
	// LogDownloadDenied is synchronous and fsync'd before the redirect above is issued, so the
	// entry is guaranteed to already be on disk here - no sleep needed.
	content, err := os.ReadFile("test/data/audit.jsonl")
	test.IsNil(t, err)
	test.IsEqualBool(t, strings.Contains(string(content), `"fileId":"`+unknownId+`"`), true)
	test.IsEqualBool(t, strings.Contains(string(content), `"outcome":"denied"`), true)
}

func TestError(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://localhost:53843/error",
		RequiredContent: []string{"The link may have expired or the file has been downloaded too many times"},
		IsHtml:          true,
	})
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://localhost:53843/error?e2e",
		RequiredContent: []string{"This file is encrypted, but no key was provided"},
		IsHtml:          true,
	})
}

func TestForgotPw(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://localhost:53843/forgotpw",
		RequiredContent: []string{"--reconfigure"},
		IsHtml:          true,
	})
}

func TestLoginCorrect(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:         "http://localhost:53843/login",
		RedirectUrl: "admin",
		Method:      "POST",
		PostValues:  []test.PostBody{{"username", "test"}, {"password", "adminadmin"}, {"csrf-token", csrftoken.Generate(csrftoken.TypeLogin)}},
	})
}

func TestLoginIncorrectPassword(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://localhost:53843/login",
		RequiredContent: []string{"Incorrect username or password"},
		IsHtml:          true,
		Method:          "POST",
		PostValues:      []test.PostBody{{"username", "test"}, {"password", "incorrect"}, {"csrf-token", csrftoken.Generate(csrftoken.TypeLogin)}},
	})
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://localhost:53843/login",
		RequiredContent: []string{"The login page was open too long and expired. Please try again."},
		IsHtml:          true,
		Method:          "POST",
		PostValues:      []test.PostBody{{"username", "test"}, {"password", "incorrect"}, {"csrf-token", "incorrect"}},
	})
}
func TestLoginIncorrectUsername(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://localhost:53843/login",
		RequiredContent: []string{"Incorrect username or password"},
		IsHtml:          true,
		Method:          "POST",
		PostValues:      []test.PostBody{{"username", "incorrect"}, {"password", "incorrect"}, {"csrf-token", csrftoken.Generate(csrftoken.TypeLogin)}},
	})
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://localhost:53843/login",
		RequiredContent: []string{"The login page was open too long and expired. Please try again."},
		IsHtml:          true,
		Method:          "POST",
		PostValues:      []test.PostBody{{"username", "incorrect"}, {"password", "incorrect"}, {"csrf-token", "incorrect"}},
	})
}

func TestLogout(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://localhost:53843/admin",
		RequiredContent: []string{"Downloads remaining"},
		IsHtml:          true,
		Cookies: []test.Cookie{{
			Name:  "session_token",
			Value: "logoutsession",
		}},
	})
	// Logout
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:         "http://localhost:53843/logout",
		RedirectUrl: "login",
		Cookies: []test.Cookie{{
			Name:  "session_token",
			Value: "logoutsession",
		}},
	})
	// Admin after logout
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:         "http://localhost:53843/admin",
		RedirectUrl: "login",
		Cookies: []test.Cookie{{
			Name:  "session_token",
			Value: "logoutsession",
		}},
	})
}

func TestDownloadHotlink(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://127.0.0.1:53843/hotlink/PhSs6mFtf8O5YGlLMfNw9rYXx9XRNkzCnJZpQBi7inunv3Z4A.jpg",
		RequiredContent: []string{"123"},
	})
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://127.0.0.1:53843/h/wjqlzpq2.jpg",
		RequiredContent: []string{"123"},
	})
	// Download expired hotlink
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://127.0.0.1:53843/hotlink/PhSs6mFtf8O5YGlLMfNw9rYXx9XRNkzCnJZpQBi7inunv3Z4A.jpg",
		RequiredContent: []string{"The requested file has expired"},
	})
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://127.0.0.1:53843/h/wjqlzpq2.jpg",
		RequiredContent: []string{"The requested file has expired"},
	})
}

func TestDownloadNoPassword(t *testing.T) {
	t.Parallel()
	// Show download page
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://127.0.0.1:53843/d?id=Wzol7LyY2QVczXynJtVo",
		IsHtml:          true,
		RequiredContent: []string{"smallfile2", "Retention period"}, // W7 privacy notice
	})
	// Download
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://127.0.0.1:53843/downloadFile?id=Wzol7LyY2QVczXynJtVo",
		RequiredContent: []string{"789"},
	})
	// Show download page expired file
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:                "http://127.0.0.1:53843/d?id=Wzol7LyY2QVczXynJtVo",
		IgnoreRedirectParm: true,
		RedirectUrl:        "error",
	})
	// Download expired file
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:                "http://127.0.0.1:53843/downloadFile?id=Wzol7LyY2QVczXynJtVo",
		IgnoreRedirectParm: true,
		RedirectUrl:        "error",
	})
}

func TestDownloadPagePassword(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://127.0.0.1:53843/d?id=jpLXGJKigM4hjtA6T6sN",
		IsHtml:          true,
		RequiredContent: []string{"Password required", "Retention period"}, // W7 privacy notice
	})
}
func TestDownloadPageIncorrectPassword(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://127.0.0.1:53843/d?id=jpLXGJKigM4hjtA6T6sN",
		IsHtml:          true,
		RequiredContent: []string{"Incorrect password!"},
		Method:          "POST",
		PostValues:      []test.PostBody{{"password", "incorrect"}},
	})
}

func TestDownloadIncorrectPasswordCookie(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://127.0.0.1:53843/d?id=jpLXGJKigM4hjtA6T6sN",
		IsHtml:          true,
		RequiredContent: []string{"Password required"},
		Cookies:         []test.Cookie{{"pjpLXGJKigM4hjtA6T6sN", "invalid"}},
	})
}

func TestDownloadIncorrectPassword(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:         "http://127.0.0.1:53843/downloadFile?id=jpLXGJKigM4hjtA6T6sN",
		RedirectUrl: "d?id=jpLXGJKigM4hjtA6T6sN",
		Cookies:     []test.Cookie{{"pjpLXGJKigM4hjtA6T6sN", "invalid"}},
	})
}

func TestDownloadCorrectPassword(t *testing.T) {
	t.Parallel()
	// Submit download page correct password
	cookies := test.HttpPageResult(t, test.HttpTestConfig{
		Url:         "http://127.0.0.1:53843/d?id=jpLXGJKigM4hjtA6T6sN2",
		RedirectUrl: "d?id=jpLXGJKigM4hjtA6T6sN2",
		Method:      "POST",
		PostValues:  []test.PostBody{{"password", "123"}},
	})
	pwCookie := ""
	for _, cookie := range cookies {
		if (*cookie).Name == "pjpLXGJKigM4hjtA6T6sN2" {
			pwCookie = (*cookie).Value
			break
		}
	}
	if pwCookie == "" {
		t.Error("Cookie not set")
	}
	// Show download page correct password
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://127.0.0.1:53843/d?id=jpLXGJKigM4hjtA6T6sN2",
		IsHtml:          true,
		RequiredContent: []string{"smallfile"},
		Cookies:         []test.Cookie{{"pjpLXGJKigM4hjtA6T6sN2", pwCookie}},
	})
	// Download correct password
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://127.0.0.1:53843/downloadFile?id=jpLXGJKigM4hjtA6T6sN2",
		RequiredContent: []string{"456"},
		Cookies:         []test.Cookie{{"pjpLXGJKigM4hjtA6T6sN2", pwCookie}},
	})
}

func TestPostUploadNoAuth(t *testing.T) {
	t.Parallel()
	test.HttpPostUploadRequest(t, test.HttpTestConfig{
		Url:             "http://127.0.0.1:53843/uploadChunk",
		UploadFileName:  "test/fileupload.jpg",
		ResultCode:      http.StatusUnauthorized,
		UploadFieldName: "file",

		RequiredContent: []string{"{\"Result\":\"error\",\"ErrorMessage\":\"Not authenticated\"}"},
	})
}

func TestPostUpload(t *testing.T) {
	// Open the SSE connection
	req, err := http.NewRequest("GET", "http://127.0.0.1:53843/uploadStatus", nil)
	test.IsNil(t, err)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cookie", "session_token=validsession")

	resp, err := http.DefaultClient.Do(req)
	test.IsNil(t, err)
	defer resp.Body.Close()

	test.IsEqualInt(t, resp.StatusCode, http.StatusOK)
	scanner := bufio.NewScanner(resp.Body)

	test.HttpPostUploadRequest(t, test.HttpTestConfig{
		Url:             "http://127.0.0.1:53843/uploadChunk",
		UploadFileName:  "test/fileupload.jpg",
		UploadFieldName: "file",
		PostValues: []test.PostBody{{
			Key:   "dztotalfilesize",
			Value: "50",
		}, {
			Key:   "dzchunkbyteoffset",
			Value: "0",
		}, {
			Key:   "dzuuid",
			Value: "eeng4ier3Taen7a",
		}},
		RequiredContent: []string{"{\"result\":\"OK\"}"},
		ExcludedContent: []string{"\"Id\":\"\"", "HotlinkId\":\"\"", "ErrorMessage"},
		Cookies: []test.Cookie{{
			Name:  "session_token",
			Value: "validsession",
		}},
	})
	go func() {
		time.Sleep(200 * time.Millisecond)
		test.HttpPostRequest(t, test.HttpTestConfig{
			Url: "http://127.0.0.1:53843/api/chunk/complete",
			Headers: []test.Header{
				{"apikey", "validkeyid7"},
				{"uuid", "eeng4ier3Taen7a"},
				{"filename", "fileupload.jpg"},
				{"filecontenttype", "test-content"},
				{"filesize", "50"},
				{"nonblocking", "true"},
			},
			RequiredContent: []string{"{\"result\":\"OK\"}"},
			Cookies: []test.Cookie{{
				Name:  "session_token",
				Value: "validsession",
			}},
		})
	}()

	var receivedStatus eventUploadStatus
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data:") {
			message := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			t.Log(message)
			err = json.Unmarshal([]byte(message), &receivedStatus)
			test.IsNil(t, err)
			if receivedStatus.UploadStatus == processingstatus.StatusFinished {
				break
			}
		}
	}
	test.IsEqualInt(t, receivedStatus.UploadStatus, processingstatus.StatusFinished)
	test.IsNotEmpty(t, receivedStatus.FileId)
	err = scanner.Err()
	test.IsNil(t, err)
	file, ok := database.GetMetaDataById(receivedStatus.FileId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, file.Name, "fileupload.jpg")
}

// Originally declared in Sse, but should not be public
type eventUploadStatus struct {
	Event        string `json:"event"`
	ChunkId      string `json:"chunk_id"`
	FileId       string `json:"file_id"`
	ErrorMessage string `json:"error_message"`
	UploadStatus int    `json:"upload_status"`
}

func TestApiPageAuthorized(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://127.0.0.1:53843/apiKeys",
		IsHtml:          true,
		RequiredContent: []string{"Click on the API key name to give it a new name."},
		Cookies: []test.Cookie{{
			Name:  "session_token",
			Value: "validsession",
		}},
	})
}
func TestApiPageNotAuthorized(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://127.0.0.1:53843/apiKeys",
		RedirectUrl:     "login",
		ResultCode:      http.StatusTemporaryRedirect,
		ExcludedContent: []string{"Click on the API key name to give it a new name."},
		Cookies: []test.Cookie{{
			Name:  "session_token",
			Value: "invalid",
		}},
	})
}

func TestProcessApi(t *testing.T) {
	// Not authorised
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://127.0.0.1:53843/api/files/list",
		RequiredContent: []string{`{"Result":"error","ErrorMessage":"Unauthorized","ErrorCode":2}`},
		ExcludedContent: []string{"smallfile2"},
		ResultCode:      401,
		Cookies: []test.Cookie{{
			Name:  "session_token",
			Value: "invalid",
		}},
	})
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://127.0.0.1:53843/api/files/list",
		RequiredContent: []string{`{"Result":"error","ErrorMessage":"Unauthorized","ErrorCode":2}`},
		ExcludedContent: []string{"smallfile2"},
		ResultCode:      401,
		Headers:         []test.Header{{"apikey", "invalid"}},
	})

	// Valid session does not grant API access
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://127.0.0.1:53843/api/files/list",
		RequiredContent: []string{`{"Result":"error","ErrorMessage":"Unauthorized","ErrorCode":2}`},
		ExcludedContent: []string{"smallfile2"},
		ResultCode:      401,
		Cookies: []test.Cookie{{
			Name:  "session_token",
			Value: "validsession",
		}},
	})
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://127.0.0.1:53843/api/files/list",
		RequiredContent: []string{"smallfile2"},
		ExcludedContent: []string{"Unauthorized"},
		Headers:         []test.Header{{"apikey", "validkey"}},
	})
}

func TestDisableLogin(t *testing.T) {
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:         "http://localhost:53843/admin",
		RedirectUrl: "login",
		Cookies: []test.Cookie{{
			Name:  "session_token",
			Value: "invalid",
		}},
	})
	configuration.Get().Authentication.Method = models.AuthenticationDisabled
	authentication.Init(configuration.Get().Authentication)
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://localhost:53843/admin",
		RequiredContent: []string{"Downloads remaining"},
		IsHtml:          true,
		Cookies: []test.Cookie{{
			Name:  "session_token",
			Value: "invalid",
		}},
	})
	configuration.Get().Authentication.Method = models.AuthenticationInternal
	authentication.Init(configuration.Get().Authentication)
}

func TestResponseError(t *testing.T) {
	w, _ := test.GetRecorder("GET", "/", nil, nil, nil)
	responseError(w, errors.New("testerror"))
	test.IsEqualInt(t, w.Result().StatusCode, 400)
	test.ResponseBodyContains(t, w, "testerror")
}

func TestServeWasmDownloader(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:    "http://localhost:53843/main.wasm",
		IsHtml: false,
	})
}
func TestServeWasmE2E(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:    "http://localhost:53843/e2e.wasm",
		IsHtml: false,
	})
}

// TestPublicApiFileUnprotected tests GET /pubapi/file for an unprotected file
func TestPublicApiFileUnprotected(t *testing.T) {
	t.Parallel()
	// Seed a dedicated file with unlimited downloads so that parallel download
	// tests (which exhaust the single-download seed files) cannot race this one.
	// Reuses the existing on-disk SHA1 backing file so storage.FileExists passes.
	database.SaveMetaData(models.File{
		Id:                 "pubapifileunprot1234",
		Name:               "smallfile2",
		Size:               "8 B",
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ExpireAt:           2147483646,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		ContentType:        "text/html",
		UserId:             5,
	})
	client := &http.Client{}
	resp, err := client.Get("http://127.0.0.1:53843/pubapi/file?id=pubapifileunprot1234")
	if err != nil {
		t.Errorf("Failed to make request: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}

	// Verify the response contains the expected fields
	if id, ok := response["id"]; !ok || id != "pubapifileunprot1234" {
		t.Errorf("Expected id 'pubapifileunprot1234', got %v", id)
	}
	if name, ok := response["name"]; !ok || name != "smallfile2" {
		t.Errorf("Expected name 'smallfile2', got %v", name)
	}
	if size, ok := response["size"]; !ok || size != "8 B" {
		t.Errorf("Expected size '8 B', got %v", size)
	}
	if requiresPw, ok := response["requiresPassword"]; !ok || requiresPw != false {
		t.Errorf("Expected requiresPassword false, got %v", requiresPw)
	}
	if _, ok := response["expiresAt"]; !ok {
		t.Errorf("Missing expiresAt field")
	}
	if _, ok := response["downloadsRemaining"]; !ok {
		t.Errorf("Missing downloadsRemaining field")
	}
	if contentType, ok := response["contentType"]; !ok || contentType != "text/html" {
		t.Errorf("Expected contentType 'text/html', got %v", contentType)
	}
}

// TestPublicApiFilePasswordProtected tests GET /pubapi/file for a password-protected file
func TestPublicApiFilePasswordProtected(t *testing.T) {
	t.Parallel()
	client := &http.Client{}
	resp, err := client.Get("http://127.0.0.1:53843/pubapi/file?id=jpLXGJKigM4hjtA6T6sN")
	if err != nil {
		t.Errorf("Failed to make request: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}

	// Verify that filename is hidden for password-protected files
	if id, ok := response["id"]; !ok || id != "jpLXGJKigM4hjtA6T6sN" {
		t.Errorf("Expected id 'jpLXGJKigM4hjtA6T6sN', got %v", id)
	}
	if name, ok := response["name"]; !ok || name != "" {
		t.Errorf("Expected name to be empty for password-protected file, got %v", name)
	}
	if requiresPw, ok := response["requiresPassword"]; !ok || requiresPw != true {
		t.Errorf("Expected requiresPassword true, got %v", requiresPw)
	}
	if contentType, ok := response["contentType"]; !ok || contentType != "" {
		t.Errorf("Expected contentType to be empty for password-protected file, got %v", contentType)
	}
}

// TestPublicApiFilePasswordProtectedWithCookie tests GET /pubapi/file for a password-protected file with valid cookie
func TestPublicApiFilePasswordProtectedWithCookie(t *testing.T) {
	t.Parallel()
	// First, get a valid password cookie by authenticating
	client := &http.Client{}
	data := strings.NewReader("password=123")
	resp, err := client.Post("http://127.0.0.1:53843/pubapi/filepassword?id=jpLXGJKigM4hjtA6T6sN", "application/x-www-form-urlencoded", data)
	if err != nil {
		t.Errorf("Failed to authenticate: %v", err)
		return
	}
	defer resp.Body.Close()

	// Get the cookie from the response
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "pjpLXGJKigM4hjtA6T6sN" {
			cookie = c
			break
		}
	}

	if cookie == nil {
		t.Errorf("Expected password cookie to be set")
		return
	}

	// Now make a request to /pubapi/file with the cookie
	req, err := http.NewRequest("GET", "http://127.0.0.1:53843/pubapi/file?id=jpLXGJKigM4hjtA6T6sN", nil)
	if err != nil {
		t.Errorf("Failed to create request: %v", err)
		return
	}
	req.AddCookie(cookie)

	resp, err = client.Do(req)
	if err != nil {
		t.Errorf("Failed to make request: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}

	// Verify that filename is revealed when a valid cookie is present
	if name, ok := response["name"]; !ok || name == "" {
		t.Errorf("Expected name to be revealed for password-protected file with valid cookie, got %v", name)
	}
	if contentType, ok := response["contentType"]; !ok || contentType == "" {
		t.Errorf("Expected contentType to be revealed for password-protected file with valid cookie, got %v", contentType)
	}
}

// TestPublicApiFileNotFound tests GET /pubapi/file for a non-existent file
func TestPublicApiFileNotFound(t *testing.T) {
	t.Parallel()
	client := &http.Client{}
	resp, err := client.Get("http://127.0.0.1:53843/pubapi/file?id=unknownfileid123456")
	if err != nil {
		t.Errorf("Failed to make request: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", resp.StatusCode)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}

	if error, ok := response["error"]; !ok || error != "not found" {
		t.Errorf("Expected error 'not found', got %v", error)
	}
}

// TestPublicApiFilePasswordWrong tests POST /pubapi/filepassword with wrong password
func TestPublicApiFilePasswordWrong(t *testing.T) {
	t.Parallel()
	client := &http.Client{}
	data := strings.NewReader("password=wrongpassword")
	resp, err := client.Post("http://127.0.0.1:53843/pubapi/filepassword?id=jpLXGJKigM4hjtA6T6sN", "application/x-www-form-urlencoded", data)
	if err != nil {
		t.Errorf("Failed to make request: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}

	if ok, exists := response["ok"]; !exists || ok != false {
		t.Errorf("Expected ok false, got %v", ok)
	}

	// Verify no password cookie was set
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "pjpLXGJKigM4hjtA6T6sN" {
			t.Errorf("Expected no password cookie to be set, but found one")
		}
	}
}

// TestPublicApiFilePasswordCorrect tests POST /pubapi/filepassword with correct password
func TestPublicApiFilePasswordCorrect(t *testing.T) {
	t.Parallel()
	client := &http.Client{}
	data := strings.NewReader("password=123")
	resp, err := client.Post("http://127.0.0.1:53843/pubapi/filepassword?id=jpLXGJKigM4hjtA6T6sN", "application/x-www-form-urlencoded", data)
	if err != nil {
		t.Errorf("Failed to make request: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}

	if ok, exists := response["ok"]; !exists || ok != true {
		t.Errorf("Expected ok true, got %v", ok)
	}

	// Verify the password cookie was set
	pwCookieFound := false
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "pjpLXGJKigM4hjtA6T6sN" {
			pwCookieFound = true
			if cookie.HttpOnly != true {
				t.Errorf("Expected cookie to be HttpOnly")
			}
			if cookie.Path != "/" {
				t.Errorf("Expected cookie Path to be '/', got '%s'", cookie.Path)
			}
			break
		}
	}

	if !pwCookieFound {
		t.Errorf("Expected password cookie pjpLXGJKigM4hjtA6T6sN to be set")
	}
}

// TestPublicApiFilePasswordTrimMatchesSetTrim closes the trim asymmetry: ValidateSharePassword
// trims leading/trailing whitespace before hashing whatever password protects a share
// (Configuration.go), so the stored hash always corresponds to the TRIMMED value regardless of
// which endpoint set it. pubApiFilePassword must trim the same way before calling VerifyPassword,
// or the exact string an uploader typed (with surrounding whitespace preserved) would be rejected
// and only the trimmed form would ever unlock the file. The stored hash here is built exactly the
// way ValidateSharePassword+HashPassword build it at set time; the verify call below sends the
// untrimmed original.
func TestPublicApiFilePasswordTrimMatchesSetTrim(t *testing.T) {
	t.Parallel()
	const rawPassword = "  Trim12Chars!  "
	trimmedHash := configuration.HashPassword(strings.TrimSpace(rawPassword), false, "")

	fileId := "trimpwtest" + helper.GenerateRandomString(8)
	database.SaveMetaData(models.File{
		Id:                 fileId,
		Name:               "trimpwtest.txt",
		Size:               "10 B",
		SizeBytes:          10,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ExpireAt:           2147483646,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		ContentType:        "text/plain",
		UserId:             999,
		PasswordHash:       trimmedHash,
	})

	client := &http.Client{}
	payload, err := json.Marshal(map[string]string{"password": rawPassword})
	if err != nil {
		t.Fatalf("Failed to marshal payload: %v", err)
	}
	req, err := http.NewRequest("POST", "http://127.0.0.1:53843/pubapi/filepassword?id="+fileId, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to make POST request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if ok, exists := response["ok"].(bool); !exists || !ok {
		t.Errorf("Expected ok=true for the untrimmed password matching a trimmed-at-set hash, got %v", response["ok"])
	}
}

// TestPublicApiFolderPasswordTrimMatchesSetTrim is the folder-bundle counterpart of
// TestPublicApiFilePasswordTrimMatchesSetTrim - pubApiFolderPassword must trim the submitted
// password the same way before verifying against every protected member's hash.
func TestPublicApiFolderPasswordTrimMatchesSetTrim(t *testing.T) {
	t.Parallel()
	const rawPassword = "  FolderTrim12!  "
	trimmedHash := configuration.HashPassword(strings.TrimSpace(rawPassword), false, "")

	bundle := filebundle.Create("TestFolderTrimPw_"+helper.GenerateRandomString(8), 999)
	database.SaveMetaData(models.File{
		Id:                 helper.GenerateRandomString(16),
		Name:               "trimfolder.txt",
		Size:               "10 B",
		SizeBytes:          10,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ExpireAt:           2147483646,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		ContentType:        "text/plain",
		UserId:             999,
		BundleId:           bundle.Id,
		PasswordHash:       trimmedHash,
	})

	client := &http.Client{}
	payload, err := json.Marshal(map[string]string{"password": rawPassword})
	if err != nil {
		t.Fatalf("Failed to marshal payload: %v", err)
	}
	req, err := http.NewRequest("POST", "http://127.0.0.1:53843/pubapi/folderpassword?id="+bundle.Id, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to make POST request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if ok, exists := response["ok"].(bool); !exists || !ok {
		t.Errorf("Expected ok=true for the untrimmed password matching a trimmed-at-set hash, got %v", response["ok"])
	}
}

// TestPublicApiUploadRequestValid tests GET /pubapi/uploadrequest for a valid request
func TestPublicApiUploadRequestValid(t *testing.T) {
	t.Parallel()

	// Create a test file request
	testRequest := models.FileRequest{
		Id:       "testuploadreq123456",
		UserId:   5,
		MaxFiles: 10,
		MaxSize:  100,
		Expiry:   time.Now().Add(24 * time.Hour).Unix(),
		Name:     "Test Upload Request",
		ApiKey:   "testkey123",
		Notes:    "Test notes",
	}
	database.SaveFileRequest(testRequest)

	client := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:53843/pubapi/uploadrequest?id=testuploadreq123456", nil)
	if err != nil {
		t.Errorf("Failed to build request: %v", err)
		return
	}
	req.Header.Set("apikey", "testkey123")
	resp, err := client.Do(req)
	if err != nil {
		t.Errorf("Failed to make request: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}

	if valid, ok := response["valid"]; !ok || valid != true {
		t.Errorf("Expected valid true, got %v", valid)
	}
	if name, ok := response["name"]; !ok || name != "Test Upload Request" {
		t.Errorf("Expected name 'Test Upload Request', got %v", name)
	}
	if maxFiles, ok := response["maxFiles"]; !ok || int(maxFiles.(float64)) != 10 {
		t.Errorf("Expected maxFiles 10, got %v", maxFiles)
	}
	if _, ok := response["chunkSize"]; !ok {
		t.Errorf("Missing chunkSize field")
	}
	// The chunked guest-upload endpoints authenticate with this key, and an
	// authorised caller needs it handed back the same way any other link
	// holder already has it in the URL.
	if apiKey, ok := response["apikey"]; !ok || apiKey != "testkey123" {
		t.Errorf("Expected apikey 'testkey123', got %v", apiKey)
	}
}

// TestPublicApiUploadRequestKeyInQueryStringRejected tests that GET /pubapi/uploadrequest
// no longer accepts the API key via the `key` query parameter (it must be sent as the
// `apikey` request header instead, so it never lands in access logs).
func TestPublicApiUploadRequestKeyInQueryStringRejected(t *testing.T) {
	t.Parallel()

	testRequest := models.FileRequest{
		Id:       "testuploadreqquery12",
		UserId:   5,
		MaxFiles: 10,
		MaxSize:  100,
		Expiry:   time.Now().Add(24 * time.Hour).Unix(),
		Name:     "Test Upload Request",
		ApiKey:   "testkey123",
		Notes:    "Test notes",
	}
	database.SaveFileRequest(testRequest)

	client := &http.Client{}
	resp, err := client.Get("http://127.0.0.1:53843/pubapi/uploadrequest?id=testuploadreqquery12&key=testkey123")
	if err != nil {
		t.Errorf("Failed to make request: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404 when key is only in query string, got %d", resp.StatusCode)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}

	if error, ok := response["error"]; !ok || error != "not found" {
		t.Errorf("Expected error 'not found', got %v", error)
	}
}

// TestPublicApiUploadRequestExpired tests GET /pubapi/uploadrequest for an expired request
func TestPublicApiUploadRequestExpired(t *testing.T) {
	t.Parallel()

	// Create an expired test file request
	testRequest := models.FileRequest{
		Id:       "expireduploadreq1234",
		UserId:   5,
		MaxFiles: 10,
		MaxSize:  100,
		Expiry:   time.Now().Add(-1 * time.Hour).Unix(), // Already expired
		Name:     "Expired Upload Request",
		ApiKey:   "expiredkey123",
		Notes:    "Test notes",
	}
	database.SaveFileRequest(testRequest)

	client := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:53843/pubapi/uploadrequest?id=expireduploadreq1234", nil)
	if err != nil {
		t.Errorf("Failed to build request: %v", err)
		return
	}
	req.Header.Set("apikey", "expiredkey123")
	resp, err := client.Do(req)
	if err != nil {
		t.Errorf("Failed to make request: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}

	if valid, ok := response["valid"]; !ok || valid != false {
		t.Errorf("Expected valid false, got %v", valid)
	}
	if reason, ok := response["reason"]; !ok || reason != "expired" {
		t.Errorf("Expected reason 'expired', got %v", reason)
	}
}

// TestPublicApiUploadRequestClosed tests GET /pubapi/uploadrequest for a request that was marked
// complete while it was still neither full nor expired
func TestPublicApiUploadRequestClosed(t *testing.T) {
	t.Parallel()

	testRequest := models.FileRequest{
		Id:       "closeduploadreq12345",
		UserId:   5,
		MaxFiles: 10,
		MaxSize:  100,
		Name:     "Closed Upload Request",
		ApiKey:   "closedkey123",
		Notes:    "Test notes",
		Closed:   true,
	}
	database.SaveFileRequest(testRequest)

	client := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:53843/pubapi/uploadrequest?id=closeduploadreq12345", nil)
	if err != nil {
		t.Errorf("Failed to build request: %v", err)
		return
	}
	req.Header.Set("apikey", "closedkey123")
	resp, err := client.Do(req)
	if err != nil {
		t.Errorf("Failed to make request: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}

	if valid, ok := response["valid"]; !ok || valid != false {
		t.Errorf("Expected valid false, got %v", valid)
	}
	if reason, ok := response["reason"]; !ok || reason != "closed" {
		t.Errorf("Expected reason 'closed', got %v", reason)
	}
	// A closed request still reports what it collected - being told it is finished is exactly
	// when someone wants to confirm what they sent arrived.
	if _, ok := response["receivedFiles"]; !ok {
		t.Error("Expected receivedFiles to be present")
	}
}

// TestPublicApiUploadRequestWrongKey tests GET /pubapi/uploadrequest with wrong key
func TestPublicApiUploadRequestWrongKey(t *testing.T) {
	t.Parallel()

	// Create a test file request
	testRequest := models.FileRequest{
		Id:       "testuploadreqkey1234",
		UserId:   5,
		MaxFiles: 10,
		MaxSize:  100,
		Expiry:   time.Now().Add(24 * time.Hour).Unix(),
		Name:     "Test Upload Request",
		ApiKey:   "testkey123",
		Notes:    "Test notes",
	}
	database.SaveFileRequest(testRequest)

	client := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:53843/pubapi/uploadrequest?id=testuploadreqkey1234", nil)
	if err != nil {
		t.Errorf("Failed to build request: %v", err)
		return
	}
	req.Header.Set("apikey", "wrongkey")
	resp, err := client.Do(req)
	if err != nil {
		t.Errorf("Failed to make request: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", resp.StatusCode)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}

	if error, ok := response["error"]; !ok || error != "not found" {
		t.Errorf("Expected error 'not found', got %v", error)
	}
}

// uploadRequestShareLoginTokenHash hashes a raw token the same way
// shareaccess.hashToken does, so a test can plant a login token directly in
// the database without a mail round-trip. hashToken is unexported, so the
// hashing is duplicated here rather than exposed just for tests.
func uploadRequestShareLoginTokenHash(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}

// TestPublicApiUploadRequestRestrictedNoCredential is a regression test for the bug this change
// fixes: a file request mailed to named recipients (shareaccess.GrantAccess) produced a link of
// the form /r/<id>?token=<token>, but pubApiUploadRequest never looked at the token or the
// recipient list at all, so a mailed recipient landed on "link is not valid". This asserts that a
// restricted request refuses an anonymous caller holding neither a token nor a cookie.
func TestPublicApiUploadRequestRestrictedNoCredential(t *testing.T) {
	t.Parallel()
	testRequest := models.FileRequest{
		Id:       "restricteduploadreq1",
		UserId:   5,
		MaxFiles: 10,
		MaxSize:  100,
		Expiry:   time.Now().Add(24 * time.Hour).Unix(),
		Name:     "Restricted Upload Request",
		ApiKey:   "restrictedkey1",
		Notes:    "Test notes",
	}
	database.SaveFileRequest(testRequest)

	recipientId := database.SaveShareRecipient(models.ShareRecipient{
		Email:     "uploadrecipient-none@example.com",
		CreatedAt: time.Now().Unix(),
	})
	database.SetShareGrants(models.ShareResourceFileRequest, testRequest.Id, []int{recipientId}, 5, 0)
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceFileRequest, testRequest.Id)
		database.DeleteShareRecipient(recipientId)
	})

	resp, err := http.Get("http://127.0.0.1:53843/pubapi/uploadrequest?id=" + testRequest.Id)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}
	if valid, ok := response["valid"]; !ok || valid != false {
		t.Errorf("Expected valid false, got %v", valid)
	}
	if reason, ok := response["reason"]; !ok || reason != "identity" {
		t.Errorf("Expected reason 'identity', got %v", reason)
	}
}

// TestPublicApiUploadRequestRestrictedApiKeyOnlyDenied asserts that the apikey header, which is
// enough to reach an unrestricted request, does not unlock one that has been restricted to named
// recipients - the recipient list supersedes the link credential, the same rule already applied
// to identity-restricted files.
func TestPublicApiUploadRequestRestrictedApiKeyOnlyDenied(t *testing.T) {
	t.Parallel()
	testRequest := models.FileRequest{
		Id:       "restricteduploadreq2",
		UserId:   5,
		MaxFiles: 10,
		MaxSize:  100,
		Expiry:   time.Now().Add(24 * time.Hour).Unix(),
		Name:     "Restricted Upload Request",
		ApiKey:   "restrictedkey2",
		Notes:    "Test notes",
	}
	database.SaveFileRequest(testRequest)

	recipientId := database.SaveShareRecipient(models.ShareRecipient{
		Email:     "uploadrecipient-apikey@example.com",
		CreatedAt: time.Now().Unix(),
	})
	database.SetShareGrants(models.ShareResourceFileRequest, testRequest.Id, []int{recipientId}, 5, 0)
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceFileRequest, testRequest.Id)
		database.DeleteShareRecipient(recipientId)
	})

	client := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:53843/pubapi/uploadrequest?id="+testRequest.Id, nil)
	if err != nil {
		t.Fatalf("Failed to build request: %v", err)
	}
	req.Header.Set("apikey", "restrictedkey2")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}
	if valid, ok := response["valid"]; !ok || valid != false {
		t.Errorf("Expected valid false, got %v", valid)
	}
	if reason, ok := response["reason"]; !ok || reason != "identity" {
		t.Errorf("Expected reason 'identity', got %v", reason)
	}
}

// TestPublicApiUploadRequestRestrictedValidToken covers the ?token= query-string fallback: the
// mailed link itself now carries the token in the URL fragment (never sent to the server), but
// links mailed before that change, and any direct (non-JS) request, still present it in the
// query string, so recipientFor must keep accepting it. It is exchanged for an sr_<id> cookie
// (shareaccess.WriteCookie via recipientFor), the response reports valid:true, and it carries
// the request's apikey so the SPA's chunked guest-upload endpoints (/api/uploadrequest/chunk/*)
// can authenticate without ever having had the header credential of their own.
func TestPublicApiUploadRequestRestrictedValidToken(t *testing.T) {
	t.Parallel()
	testRequest := models.FileRequest{
		Id:       "restricteduploadreq3",
		UserId:   5,
		MaxFiles: 10,
		MaxSize:  100,
		Expiry:   time.Now().Add(24 * time.Hour).Unix(),
		Name:     "Restricted Upload Request",
		ApiKey:   "restrictedkey3",
		Notes:    "Test notes",
	}
	database.SaveFileRequest(testRequest)

	recipientId := database.SaveShareRecipient(models.ShareRecipient{
		Email:     "uploadrecipient-token@example.com",
		CreatedAt: time.Now().Unix(),
	})
	database.SetShareGrants(models.ShareResourceFileRequest, testRequest.Id, []int{recipientId}, 5, 0)
	rawToken := "raw-uploadreq-token-valid"
	database.SaveShareLoginToken(models.ShareLoginToken{
		TokenHash:    uploadRequestShareLoginTokenHash(rawToken),
		RecipientId:  recipientId,
		ResourceType: models.ShareResourceFileRequest,
		ResourceId:   testRequest.Id,
		CreatedAt:    time.Now().Unix(),
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
	})
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceFileRequest, testRequest.Id)
		database.DeleteShareRecipient(recipientId)
	})

	resp, err := http.Get("http://127.0.0.1:53843/pubapi/uploadrequest?id=" + testRequest.Id + "&token=" + rawToken)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}
	if valid, ok := response["valid"]; !ok || valid != true {
		t.Errorf("Expected valid true, got %v", valid)
	}
	if apiKey, ok := response["apikey"]; !ok || apiKey != "restrictedkey3" {
		t.Errorf("Expected apikey 'restrictedkey3', got %v", apiKey)
	}

	expectedCookieName := shareaccess.CookieName(models.ShareResourceFileRequest, testRequest.Id)
	found := false
	for _, cookie := range resp.Cookies() {
		if cookie.Name == expectedCookieName {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected Set-Cookie for %s, got cookies %v", expectedCookieName, resp.Cookies())
	}
}

// TestPublicApiUploadRequestRestrictedSharetokenHeader is the primary path: the mailed link
// carries the token in the URL fragment, which the server never sees, so the SPA reads it out
// client-side and forwards it as the sharetoken request header instead. This asserts that header
// alone (no ?token= query param at all) is enough to authorise, exchanges for an sr_<id> cookie
// the same way the query-string fallback does, and the response carries the apikey field.
func TestPublicApiUploadRequestRestrictedSharetokenHeader(t *testing.T) {
	t.Parallel()
	testRequest := models.FileRequest{
		Id:       "restricteduploadreq5",
		UserId:   5,
		MaxFiles: 10,
		MaxSize:  100,
		Expiry:   time.Now().Add(24 * time.Hour).Unix(),
		Name:     "Restricted Upload Request",
		ApiKey:   "restrictedkey5",
		Notes:    "Test notes",
	}
	database.SaveFileRequest(testRequest)

	recipientId := database.SaveShareRecipient(models.ShareRecipient{
		Email:     "uploadrecipient-sharetoken@example.com",
		CreatedAt: time.Now().Unix(),
	})
	database.SetShareGrants(models.ShareResourceFileRequest, testRequest.Id, []int{recipientId}, 5, 0)
	rawToken := "raw-uploadreq-token-sharetoken-header"
	database.SaveShareLoginToken(models.ShareLoginToken{
		TokenHash:    uploadRequestShareLoginTokenHash(rawToken),
		RecipientId:  recipientId,
		ResourceType: models.ShareResourceFileRequest,
		ResourceId:   testRequest.Id,
		CreatedAt:    time.Now().Unix(),
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
	})
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceFileRequest, testRequest.Id)
		database.DeleteShareRecipient(recipientId)
	})

	client := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:53843/pubapi/uploadrequest?id="+testRequest.Id, nil)
	if err != nil {
		t.Fatalf("Failed to build request: %v", err)
	}
	req.Header.Set("sharetoken", rawToken)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}
	if valid, ok := response["valid"]; !ok || valid != true {
		t.Errorf("Expected valid true, got %v", valid)
	}
	if apiKey, ok := response["apikey"]; !ok || apiKey != "restrictedkey5" {
		t.Errorf("Expected apikey 'restrictedkey5', got %v", apiKey)
	}

	expectedCookieName := shareaccess.CookieName(models.ShareResourceFileRequest, testRequest.Id)
	found := false
	for _, cookie := range resp.Cookies() {
		if cookie.Name == expectedCookieName {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected Set-Cookie for %s, got cookies %v", expectedCookieName, resp.Cookies())
	}
}

// TestPublicApiUploadRequestRestrictedTokenWrongResource asserts a token issued for a different
// resource is refused rather than accepted, the same binding ValidateToken already enforces: a
// link mailed for one file request must not double as a credential for another.
func TestPublicApiUploadRequestRestrictedTokenWrongResource(t *testing.T) {
	t.Parallel()
	testRequest := models.FileRequest{
		Id:       "restricteduploadreq4",
		UserId:   5,
		MaxFiles: 10,
		MaxSize:  100,
		Expiry:   time.Now().Add(24 * time.Hour).Unix(),
		Name:     "Restricted Upload Request",
		ApiKey:   "restrictedkey4",
		Notes:    "Test notes",
	}
	database.SaveFileRequest(testRequest)

	recipientId := database.SaveShareRecipient(models.ShareRecipient{
		Email:     "uploadrecipient-wrongres@example.com",
		CreatedAt: time.Now().Unix(),
	})
	database.SetShareGrants(models.ShareResourceFileRequest, testRequest.Id, []int{recipientId}, 5, 0)
	rawToken := "raw-uploadreq-token-wrong-resource"
	database.SaveShareLoginToken(models.ShareLoginToken{
		TokenHash:    uploadRequestShareLoginTokenHash(rawToken),
		RecipientId:  recipientId,
		ResourceType: models.ShareResourceFileRequest,
		ResourceId:   "some-other-request-id",
		CreatedAt:    time.Now().Unix(),
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
	})
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceFileRequest, testRequest.Id)
		database.DeleteShareRecipient(recipientId)
	})

	resp, err := http.Get("http://127.0.0.1:53843/pubapi/uploadrequest?id=" + testRequest.Id + "&token=" + rawToken)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}
	if valid, ok := response["valid"]; !ok || valid != false {
		t.Errorf("Expected valid false, got %v", valid)
	}
	if reason, ok := response["reason"]; !ok || reason != "identity" {
		t.Errorf("Expected reason 'identity', got %v", reason)
	}
}

// TestPublicApiUploadRequestRestrictedIdentityLeakPin pins the identity refusal body to exactly
// {"valid","reason"}: today it is a string literal, but this fails loudly if a future refactor to
// json.Encode ever adds name/notes/receivedFiles/apikey to a response an anonymous caller can see.
func TestPublicApiUploadRequestRestrictedIdentityLeakPin(t *testing.T) {
	t.Parallel()
	testRequest := models.FileRequest{
		Id:       "restricteduploadreq6",
		UserId:   5,
		MaxFiles: 10,
		MaxSize:  100,
		Expiry:   time.Now().Add(24 * time.Hour).Unix(),
		Name:     "Restricted Upload Request",
		ApiKey:   "restrictedkey6",
		Notes:    "Test notes",
	}
	database.SaveFileRequest(testRequest)

	recipientId := database.SaveShareRecipient(models.ShareRecipient{
		Email:     "uploadrecipient-leakpin@example.com",
		CreatedAt: time.Now().Unix(),
	})
	database.SetShareGrants(models.ShareResourceFileRequest, testRequest.Id, []int{recipientId}, 5, 0)
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceFileRequest, testRequest.Id)
		database.DeleteShareRecipient(recipientId)
	})

	resp, err := http.Get("http://127.0.0.1:53843/pubapi/uploadrequest?id=" + testRequest.Id)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	var response map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}
	if len(response) != 2 {
		t.Errorf("Expected identity refusal body to have exactly 2 keys, got %v", response)
	}
	if _, ok := response["valid"]; !ok {
		t.Errorf("Expected key 'valid', got %v", response)
	}
	if _, ok := response["reason"]; !ok {
		t.Errorf("Expected key 'reason', got %v", response)
	}
}

// TestPublicApiUploadRequestRestrictedCookieOnly asserts the sr_ cookie minted by an earlier
// token exchange is sufficient on its own: a second request carrying only the cookie, with no
// token and no apikey, must still authorise, the same way the SPA revisits the request page after
// the fragment token has already been exchanged once.
func TestPublicApiUploadRequestRestrictedCookieOnly(t *testing.T) {
	t.Parallel()
	testRequest := models.FileRequest{
		Id:       "restricteduploadreq7",
		UserId:   5,
		MaxFiles: 10,
		MaxSize:  100,
		Expiry:   time.Now().Add(24 * time.Hour).Unix(),
		Name:     "Restricted Upload Request",
		ApiKey:   "restrictedkey7",
		Notes:    "Test notes",
	}
	database.SaveFileRequest(testRequest)

	recipientId := database.SaveShareRecipient(models.ShareRecipient{
		Email:     "uploadrecipient-cookieonly@example.com",
		CreatedAt: time.Now().Unix(),
	})
	database.SetShareGrants(models.ShareResourceFileRequest, testRequest.Id, []int{recipientId}, 5, 0)
	rawToken := "raw-uploadreq-token-cookie-only"
	database.SaveShareLoginToken(models.ShareLoginToken{
		TokenHash:    uploadRequestShareLoginTokenHash(rawToken),
		RecipientId:  recipientId,
		ResourceType: models.ShareResourceFileRequest,
		ResourceId:   testRequest.Id,
		CreatedAt:    time.Now().Unix(),
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
	})
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceFileRequest, testRequest.Id)
		database.DeleteShareRecipient(recipientId)
	})

	client := &http.Client{}
	firstResp, err := client.Get("http://127.0.0.1:53843/pubapi/uploadrequest?id=" + testRequest.Id + "&token=" + rawToken)
	if err != nil {
		t.Fatalf("Failed to make first request: %v", err)
	}
	defer firstResp.Body.Close()

	expectedCookieName := shareaccess.CookieName(models.ShareResourceFileRequest, testRequest.Id)
	var cookie *http.Cookie
	for _, c := range firstResp.Cookies() {
		if c.Name == expectedCookieName {
			cookie = c
			break
		}
	}
	if cookie == nil {
		t.Fatalf("Expected Set-Cookie for %s, got cookies %v", expectedCookieName, firstResp.Cookies())
	}

	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:53843/pubapi/uploadrequest?id="+testRequest.Id, nil)
	if err != nil {
		t.Fatalf("Failed to build request: %v", err)
	}
	req.AddCookie(cookie)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to make second request: %v", err)
	}
	defer resp.Body.Close()

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}
	if valid, ok := response["valid"]; !ok || valid != true {
		t.Errorf("Expected valid true from cookie alone, got %v", response)
	}
}

// TestPublicApiUploadRequestRestrictedExpiredIdentityOrdering pins the gate ordering the frontend
// relies on: for a request that is both restricted and expired, an anonymous caller must still see
// reason "identity" rather than "expired" - the identity check runs first, so an unauthorised
// caller learns nothing about the request's expiry. A caller holding a valid token clears the
// identity gate and then sees "expired" as normal.
func TestPublicApiUploadRequestRestrictedExpiredIdentityOrdering(t *testing.T) {
	t.Parallel()
	testRequest := models.FileRequest{
		Id:       "restricteduploadreq8",
		UserId:   5,
		MaxFiles: 10,
		MaxSize:  100,
		Expiry:   time.Now().Add(-1 * time.Hour).Unix(), // Already expired
		Name:     "Restricted Expired Upload Request",
		ApiKey:   "restrictedkey8",
		Notes:    "Test notes",
	}
	database.SaveFileRequest(testRequest)

	recipientId := database.SaveShareRecipient(models.ShareRecipient{
		Email:     "uploadrecipient-expiredorder@example.com",
		CreatedAt: time.Now().Unix(),
	})
	database.SetShareGrants(models.ShareResourceFileRequest, testRequest.Id, []int{recipientId}, 5, 0)
	rawToken := "raw-uploadreq-token-expired-order"
	database.SaveShareLoginToken(models.ShareLoginToken{
		TokenHash:    uploadRequestShareLoginTokenHash(rawToken),
		RecipientId:  recipientId,
		ResourceType: models.ShareResourceFileRequest,
		ResourceId:   testRequest.Id,
		CreatedAt:    time.Now().Unix(),
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
	})
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceFileRequest, testRequest.Id)
		database.DeleteShareRecipient(recipientId)
	})

	noCredResp, err := http.Get("http://127.0.0.1:53843/pubapi/uploadrequest?id=" + testRequest.Id)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer noCredResp.Body.Close()

	var noCredResponse map[string]interface{}
	if err := json.NewDecoder(noCredResp.Body).Decode(&noCredResponse); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}
	if valid, ok := noCredResponse["valid"]; !ok || valid != false {
		t.Errorf("Expected valid false, got %v", noCredResponse)
	}
	if reason, ok := noCredResponse["reason"]; !ok || reason != "identity" {
		t.Errorf("Expected reason 'identity' for an anonymous caller on a restricted+expired request, got %v", noCredResponse)
	}

	tokenResp, err := http.Get("http://127.0.0.1:53843/pubapi/uploadrequest?id=" + testRequest.Id + "&token=" + rawToken)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer tokenResp.Body.Close()

	var tokenResponse map[string]interface{}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenResponse); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}
	if valid, ok := tokenResponse["valid"]; !ok || valid != false {
		t.Errorf("Expected valid false, got %v", tokenResponse)
	}
	if reason, ok := tokenResponse["reason"]; !ok || reason != "expired" {
		t.Errorf("Expected reason 'expired' once the identity gate is cleared, got %v", tokenResponse)
	}
}

// TestPublicApiFolderUnprotected tests GET /pubapi/folder for an unprotected folder
func TestPublicApiFolderUnprotected(t *testing.T) {
	t.Parallel()
	// Create a test folder with files
	bundle := filebundle.Create("TestFolder_Unprotected", 5)
	database.SaveMetaData(models.File{
		Id:                 "pubfolder_file1",
		Name:               "file1.txt",
		Size:               "10 B",
		SizeBytes:          10,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ExpireAt:           2147483646,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		ContentType:        "text/plain",
		UserId:             5,
		BundleId:           bundle.Id,
	})

	client := &http.Client{}
	resp, err := client.Get("http://127.0.0.1:53843/pubapi/folder?id=" + bundle.Id)
	if err != nil {
		t.Errorf("Failed to make request: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}

	// Verify the response contains the expected fields
	if id, ok := response["id"]; !ok || id != bundle.Id {
		t.Errorf("Expected id '%s', got %v", bundle.Id, id)
	}
	if name, ok := response["name"]; !ok || name != "TestFolder_Unprotected" {
		t.Errorf("Expected name 'TestFolder_Unprotected', got %v", name)
	}
	if requiresPw, ok := response["requiresPassword"]; !ok || requiresPw != false {
		t.Errorf("Expected requiresPassword false, got %v", requiresPw)
	}
	if files, ok := response["files"]; !ok || len(files.([]interface{})) != 1 {
		t.Errorf("Expected 1 file, got %v", files)
	}
}

// TestPublicApiFolderNotFound tests GET /pubapi/folder for a non-existent folder
func TestPublicApiFolderNotFound(t *testing.T) {
	t.Parallel()
	client := &http.Client{}
	resp, err := client.Get("http://127.0.0.1:53843/pubapi/folder?id=unknownfolder123456")
	if err != nil {
		t.Errorf("Failed to make request: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", resp.StatusCode)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}

	if error, ok := response["error"]; !ok || error != "not found" {
		t.Errorf("Expected error 'not found', got %v", error)
	}
}

// TestPublicApiFolderRestrictedDeniedToAnonymous is a regression test for a broken-access-control
// bug: recipient/identity access control (mayAccessShare / IsShareRestricted with
// ShareResourceBundle) was enforced on single-file downloads (serveFile, pubApiFileMetadata) but
// never on the folder/bundle endpoints. As a result a bundle restricted to a named recipient was
// still fully readable and downloadable by anyone holding the bundle id.
//
// This asserts both /pubapi/folder and /pubapi/folderzip deny an anonymous request against a
// restricted bundle, routed to the same generic "not found" response the single-file path uses
// (so the request never confirms the id names a real bundle), and that the restricted member's
// filename is never leaked in the denial.
func TestPublicApiFolderRestrictedDeniedToAnonymous(t *testing.T) {
	t.Parallel()
	uniqueName := "TestFolderRestricted_" + helper.GenerateRandomString(8)
	bundle := filebundle.Create(uniqueName, 999)

	fileId := helper.GenerateRandomString(16)
	secretFileName := "secret_restricted_file.txt"
	database.SaveMetaData(models.File{
		Id:                 fileId,
		Name:               secretFileName,
		Size:               "10 B",
		SizeBytes:          10,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ExpireAt:           2147483646,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		ContentType:        "text/plain",
		UserId:             999,
		BundleId:           bundle.Id,
	})

	recipientId := database.SaveShareRecipient(models.ShareRecipient{
		Email:     "restricted-recipient@example.com",
		CreatedAt: time.Now().Unix(),
	})
	// Restricts the bundle to one named recipient, the same mechanism the admin
	// "set share recipients" API (shareaccess.GrantAccess) uses under the hood.
	database.SetShareGrants(models.ShareResourceBundle, bundle.Id, []int{recipientId}, 999, 0)
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceBundle, bundle.Id)
		database.DeleteShareRecipient(recipientId)
	})

	client := &http.Client{}

	folderResp, err := client.Get("http://127.0.0.1:53843/pubapi/folder?id=" + bundle.Id)
	if err != nil {
		t.Fatalf("Failed to request folder: %v", err)
	}
	defer folderResp.Body.Close()
	folderBody, _ := io.ReadAll(folderResp.Body)

	if folderResp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected /pubapi/folder for a restricted bundle to be denied as not found, got status %d, body %s", folderResp.StatusCode, folderBody)
	}
	if strings.Contains(string(folderBody), secretFileName) {
		t.Errorf("Restricted bundle member name leaked to an anonymous request: %s", folderBody)
	}

	zipResp, err := client.Get("http://127.0.0.1:53843/pubapi/folderzip?id=" + bundle.Id)
	if err != nil {
		t.Fatalf("Failed to request folderzip: %v", err)
	}
	defer zipResp.Body.Close()
	zipBody, _ := io.ReadAll(zipResp.Body)

	if zipResp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected /pubapi/folderzip for a restricted bundle to be denied as not found, got status %d", zipResp.StatusCode)
	}
	if zipResp.Header.Get("Content-Type") == "application/zip" || len(zipBody) > 0 && zipResp.Header.Get("Content-Disposition") != "" {
		t.Errorf("Restricted bundle bytes were served to an anonymous request, Content-Type=%s Content-Disposition=%s",
			zipResp.Header.Get("Content-Type"), zipResp.Header.Get("Content-Disposition"))
	}
}

// testShareAccessCookie mints a valid access cookie for a recipient the same way
// recipientFor does for a token exchange, so a test can act as an already-authorised
// recipient without a mail round-trip.
func testShareAccessCookie(resourceType int, resourceId string, recipientId int) test.Cookie {
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://127.0.0.1:53843/", nil)
	shareaccess.WriteCookie(recorder, req, resourceType, resourceId, recipientId)
	cookies := recorder.Result().Cookies()
	return test.Cookie{Name: cookies[0].Name, Value: cookies[0].Value}
}

// TestSingleFileCascadesRestrictedBundleDeniesAnonymous is a regression test for a
// broken-access-control bug: serveFile (/d, /dh, /downloadFile) and pubApiFileMetadata
// (/pubapi/file) checked only a file's own restriction, never whether the file is a member
// of a restricted bundle. A file with no grant of its own could therefore be pulled straight
// out of a restricted bundle by anyone holding the member's individual file id, bypassing the
// bundle's recipient ACL entirely.
//
// This asserts an anonymous caller is denied on both doors, routed to the same "not found"
// convention the file-level restriction already uses, and that the member's name is never
// leaked through the metadata endpoint.
func TestSingleFileCascadesRestrictedBundleDeniesAnonymous(t *testing.T) {
	t.Parallel()
	uniqueName := "TestCascade_Denied_" + helper.GenerateRandomString(8)
	bundle := filebundle.Create(uniqueName, 999)

	fileId := helper.GenerateRandomString(16)
	secretFileName := "secret_cascade_member.txt"
	database.SaveMetaData(models.File{
		Id:                 fileId,
		Name:               secretFileName,
		Size:               "3 B",
		SizeBytes:          3,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ExpireAt:           2147483646,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		ContentType:        "text/plain",
		UserId:             999,
		BundleId:           bundle.Id,
	})

	recipientId := database.SaveShareRecipient(models.ShareRecipient{
		Email:     "cascade-recipient-denied@example.com",
		CreatedAt: time.Now().Unix(),
	})
	// Restricts the bundle only - the member file itself carries no grant of its own.
	database.SetShareGrants(models.ShareResourceBundle, bundle.Id, []int{recipientId}, 999, 0)
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceBundle, bundle.Id)
		database.DeleteShareRecipient(recipientId)
		database.DeleteMetaData(fileId)
		filebundle.Delete(bundle)
	})

	// /downloadFile must deny the same way an unknown id would.
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:         "http://127.0.0.1:53843/downloadFile?id=" + fileId,
		RedirectUrl: "error",
	})

	// /pubapi/file must not leak the member's name or content type.
	client := &http.Client{}
	resp, err := client.Get("http://127.0.0.1:53843/pubapi/file?id=" + fileId)
	if err != nil {
		t.Fatalf("Failed to request file metadata: %v", err)
	}
	defer resp.Body.Close()

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if name, ok := response["name"]; !ok || name != "" {
		t.Errorf("Expected withheld name, got %v", name)
	}
	if contentType, ok := response["contentType"]; !ok || contentType != "" {
		t.Errorf("Expected withheld contentType, got %v", contentType)
	}
	if isAuthorised, ok := response["isAuthorised"]; !ok || isAuthorised != false {
		t.Errorf("Expected isAuthorised false, got %v", isAuthorised)
	}
}

// TestPublicApiFileMetadataHidesSizeExpiryForNonRecipient is a regression test: an
// identity-restricted file withheld its name and contentType from a non-recipient, but still
// returned size, expiresAt and downloadsRemaining with a 200 - the exact information the
// 404-for-non-recipients convention used by serveFile and the pubApiFolder* handlers exists to
// deny. An anonymous caller holding only the file id must not learn any of these three fields.
func TestPublicApiFileMetadataHidesSizeExpiryForNonRecipient(t *testing.T) {
	t.Parallel()
	fileId := helper.GenerateRandomString(16)
	database.SaveMetaData(models.File{
		Id:                 fileId,
		Name:               "metadata-leak-restricted.txt",
		Size:               "42 B",
		SizeBytes:          42,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ExpireAt:           2147483646,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		ContentType:        "text/plain",
		UserId:             999,
	})

	recipientId := database.SaveShareRecipient(models.ShareRecipient{
		Email:     "metadata-leak-recipient@example.com",
		CreatedAt: time.Now().Unix(),
	})
	database.SetShareGrants(models.ShareResourceFile, fileId, []int{recipientId}, 999, 0)
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceFile, fileId)
		database.DeleteShareRecipient(recipientId)
		database.DeleteMetaData(fileId)
	})

	client := &http.Client{}
	resp, err := client.Get("http://127.0.0.1:53843/pubapi/file?id=" + fileId)
	if err != nil {
		t.Fatalf("Failed to request file metadata: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if isAuthorised, ok := response["isAuthorised"]; !ok || isAuthorised != false {
		t.Errorf("Expected isAuthorised false, got %v", isAuthorised)
	}
	for _, field := range []string{"size", "expiresAt", "downloadsRemaining"} {
		if value, present := response[field]; present {
			t.Errorf("restricted file leaked %q to a non-recipient: %v", field, value)
		}
	}
}

// TestPublicApiShareResendCooldownIsIndistinguishableFromNonRecipient is a regression test for
// the resend endpoint being usable as a recipient-membership oracle: ErrCooldown was only
// reachable once the grant check inside shareaccess.ResendLink had already passed, so a caller
// hitting the endpoint twice in a row could tell a real recipient (200, then a distinct 429) from
// a stranger (200, then 200 again) purely from the second response. Every outcome, including a
// cooldown hit, must now produce the exact same status and body.
func TestPublicApiShareResendCooldownIsIndistinguishableFromNonRecipient(t *testing.T) {
	test.IsNil(t, gokapimail.InitWithConfig(gokapimail.Config{Provider: gokapimail.ProviderLog, TimeoutSeconds: 20}))
	t.Cleanup(gokapimail.ResetForTesting)

	fileId := helper.GenerateRandomString(16)
	database.SaveMetaData(models.File{
		Id:                 fileId,
		Name:               "resend-oracle.txt",
		Size:               "3 B",
		SizeBytes:          3,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ExpireAt:           2147483646,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		ContentType:        "text/plain",
		UserId:             999,
	})
	recipientId := database.SaveShareRecipient(models.ShareRecipient{
		Email:     "resend-oracle-recipient@example.com",
		CreatedAt: time.Now().Unix(),
	})
	database.SetShareGrants(models.ShareResourceFile, fileId, []int{recipientId}, 999, 0)
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceFile, fileId)
		database.DeleteShareRecipient(recipientId)
		database.DeleteMetaData(fileId)
	})

	postResend := func(email string) (int, string) {
		payload, err := json.Marshal(map[string]interface{}{
			"resourceType": models.ShareResourceFile,
			"resourceId":   fileId,
			"email":        email,
		})
		test.IsNil(t, err)
		resp, err := http.Post("http://127.0.0.1:53843/pubapi/share/resend",
			"application/json", bytes.NewReader(payload))
		if err != nil {
			t.Fatalf("resend request failed: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	// First call for the real recipient succeeds and mints a link; the second, sent
	// immediately after, is the one a previous version of this handler answered with a
	// distinct 429 because it hit the cooldown.
	recipientStatus1, recipientBody1 := postResend("resend-oracle-recipient@example.com")
	recipientStatus2, recipientBody2 := postResend("resend-oracle-recipient@example.com")

	strangerStatus1, strangerBody1 := postResend("resend-oracle-stranger@example.com")
	strangerStatus2, strangerBody2 := postResend("resend-oracle-stranger@example.com")

	if recipientStatus1 != strangerStatus1 || recipientBody1 != strangerBody1 {
		t.Errorf("first call distinguishes recipient from stranger: recipient=(%d,%s) stranger=(%d,%s)",
			recipientStatus1, recipientBody1, strangerStatus1, strangerBody1)
	}
	if recipientStatus2 != strangerStatus2 || recipientBody2 != strangerBody2 {
		t.Errorf("second call (cooldown for the recipient) distinguishes recipient from stranger: recipient=(%d,%s) stranger=(%d,%s)",
			recipientStatus2, recipientBody2, strangerStatus2, strangerBody2)
	}
	if recipientStatus2 != http.StatusOK {
		t.Errorf("expected the uniform OK response even on a cooldown hit, got %d: %s", recipientStatus2, recipientBody2)
	}
}

// TestPublicApiShareResendExpiredFileRequestMailsNothing is a regression test for bug 3:
// describeShareResource resolved a resource with a raw metadata lookup and no liveness
// check, so /pubapi/share/resend would keep mailing a valid-looking link for an
// already-expired file request indefinitely - cleanInvalidFileRequests only ever removes a
// request whose owning user is gone, never one that merely expired or was closed. This
// asserts a resend against an expired file request sends no mail (no ShareLoginToken is
// minted) and answers exactly like the unknown-address case the endpoint already handles.
func TestPublicApiShareResendExpiredFileRequestMailsNothing(t *testing.T) {
	test.IsNil(t, gokapimail.InitWithConfig(gokapimail.Config{Provider: gokapimail.ProviderLog, TimeoutSeconds: 20}))
	t.Cleanup(gokapimail.ResetForTesting)

	testRequest := models.FileRequest{
		Id:       helper.GenerateRandomString(16),
		UserId:   999,
		MaxFiles: 10,
		MaxSize:  100,
		Expiry:   time.Now().Add(-1 * time.Hour).Unix(), // already expired
		Name:     "Expired Request",
		ApiKey:   "expiredreqkey123456",
	}
	database.SaveFileRequest(testRequest)

	recipientId := database.SaveShareRecipient(models.ShareRecipient{
		Email:     "expired-request-recipient@example.com",
		CreatedAt: time.Now().Unix(),
	})
	database.SetShareGrants(models.ShareResourceFileRequest, testRequest.Id, []int{recipientId}, 999, 0)
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceFileRequest, testRequest.Id)
		database.DeleteShareRecipient(recipientId)
		database.DeleteFileRequest(testRequest)
	})

	postResend := func(email string) (int, string) {
		payload, err := json.Marshal(map[string]interface{}{
			"resourceType": models.ShareResourceFileRequest,
			"resourceId":   testRequest.Id,
			"email":        email,
		})
		test.IsNil(t, err)
		resp, err := http.Post("http://127.0.0.1:53843/pubapi/share/resend",
			"application/json", bytes.NewReader(payload))
		if err != nil {
			t.Fatalf("resend request failed: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	recipientStatus, recipientBody := postResend("expired-request-recipient@example.com")
	strangerStatus, strangerBody := postResend("expired-request-stranger@example.com")

	if recipientStatus != strangerStatus || recipientBody != strangerBody {
		t.Errorf("resend for an expired file request distinguishes its real recipient from a stranger: recipient=(%d,%s) stranger=(%d,%s)",
			recipientStatus, recipientBody, strangerStatus, strangerBody)
	}
	if recipientStatus != http.StatusOK {
		t.Errorf("expected the uniform OK response for an expired file request, got %d: %s", recipientStatus, recipientBody)
	}

	if lastIssued := database.GetLastShareLoginTokenTime(recipientId, models.ShareResourceFileRequest, testRequest.Id); lastIssued != 0 {
		t.Errorf("expected no mail to be sent (no access token minted) for an expired file request, but one was issued at %d", lastIssued)
	}
}

// TestSingleFileCascadesRestrictedBundleAllowsRecipient is the positive counterpart of
// TestSingleFileCascadesRestrictedBundleDeniesAnonymous: an authorised bundle recipient can
// still reach a member file directly through the single-file door, and doing so spends the
// bundle's own per-recipient allowance, mirroring how pubApiFolderZip meters the bundle.
func TestSingleFileCascadesRestrictedBundleAllowsRecipient(t *testing.T) {
	t.Parallel()
	uniqueName := "TestCascade_Allowed_" + helper.GenerateRandomString(8)
	bundle := filebundle.Create(uniqueName, 999)

	fileId := helper.GenerateRandomString(16)
	database.SaveMetaData(models.File{
		Id:                 fileId,
		Name:               "member.txt",
		Size:               "3 B",
		SizeBytes:          3,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ExpireAt:           2147483646,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		ContentType:        "text/plain",
		UserId:             999,
		BundleId:           bundle.Id,
	})

	recipientId := database.SaveShareRecipient(models.ShareRecipient{
		Email:     "cascade-recipient-allowed@example.com",
		CreatedAt: time.Now().Unix(),
	})
	database.SetShareGrants(models.ShareResourceBundle, bundle.Id, []int{recipientId}, 999, 5)
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceBundle, bundle.Id)
		database.DeleteShareRecipient(recipientId)
		database.DeleteMetaData(fileId)
		filebundle.Delete(bundle)
	})

	cookie := testShareAccessCookie(models.ShareResourceBundle, bundle.Id, recipientId)

	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://127.0.0.1:53843/downloadFile?id=" + fileId,
		RequiredContent: []string{"789"},
		Cookies:         []test.Cookie{cookie},
	})

	grants := database.GetShareGrants(models.ShareResourceBundle, bundle.Id)
	found := false
	for _, grant := range grants {
		if grant.RecipientId == recipientId {
			found = true
			if grant.DownloadsUsed != 1 {
				t.Errorf("Expected bundle allowance to be spent once, DownloadsUsed=%d", grant.DownloadsUsed)
			}
		}
	}
	if !found {
		t.Errorf("Expected a grant for recipient %d", recipientId)
	}
}

// TestSingleFileNoCascadeWhenBundleUnrestrictedOrAbsent is a regression test: a member of an
// unrestricted bundle, and a file that belongs to no bundle at all, must behave exactly as
// before the cascade fix - openly downloadable and with metadata fully visible, since
// IsShareRestricted(ShareResourceBundle, ...) is false in both cases and the new check must
// no-op.
func TestSingleFileNoCascadeWhenBundleUnrestrictedOrAbsent(t *testing.T) {
	t.Parallel()
	uniqueName := "TestCascade_Unrestricted_" + helper.GenerateRandomString(8)
	bundle := filebundle.Create(uniqueName, 999)

	memberFileId := helper.GenerateRandomString(16)
	database.SaveMetaData(models.File{
		Id:                 memberFileId,
		Name:               "unrestricted_member.txt",
		Size:               "3 B",
		SizeBytes:          3,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ExpireAt:           2147483646,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		ContentType:        "text/plain",
		UserId:             999,
		BundleId:           bundle.Id,
	})

	noBundleFileId := helper.GenerateRandomString(16)
	database.SaveMetaData(models.File{
		Id:                 noBundleFileId,
		Name:               "no_bundle_file.txt",
		Size:               "3 B",
		SizeBytes:          3,
		SHA1:               "c4f9375f9834b4e7f0a528cc65c055702bf5f24a",
		ExpireAt:           2147483646,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		ContentType:        "text/plain",
		UserId:             999,
	})

	t.Cleanup(func() {
		database.DeleteMetaData(memberFileId)
		database.DeleteMetaData(noBundleFileId)
		filebundle.Delete(bundle)
	})

	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://127.0.0.1:53843/downloadFile?id=" + memberFileId,
		RequiredContent: []string{"789"},
	})
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             "http://127.0.0.1:53843/downloadFile?id=" + noBundleFileId,
		RequiredContent: []string{"456"},
	})

	client := &http.Client{}
	for _, id := range []string{memberFileId} {
		resp, err := client.Get("http://127.0.0.1:53843/pubapi/file?id=" + id)
		if err != nil {
			t.Fatalf("Failed to request file metadata: %v", err)
		}
		var response map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}
		resp.Body.Close()
		if name, ok := response["name"]; !ok || name == "" {
			t.Errorf("Expected visible name for id %s, got %v", id, name)
		}
	}
}

// TestFolderZipBundleAllowanceCheckedBeforeMemberCounters is a regression test for a
// correctness nit: pubApiFolderZip used to burn every member's per-file download count (and
// each individually-restricted member's own recipient allowance) in the zip-building loop,
// and only afterwards checked and consumed the bundle's own allowance. If the bundle allowance
// turned out to be exhausted, the handler returned not-found having already spent member
// counters for a zip that was never delivered.
//
// This asserts that when the bundle's allowance for the requesting recipient is already
// exhausted, /pubapi/folderzip denies the request as not-found and leaves every member's
// DownloadCount completely untouched.
func TestFolderZipBundleAllowanceCheckedBeforeMemberCounters(t *testing.T) {
	t.Parallel()
	uniqueName := "TestZipOrdering_" + helper.GenerateRandomString(8)
	bundle := filebundle.Create(uniqueName, 999)

	file1Id := helper.GenerateRandomString(16)
	database.SaveMetaData(models.File{
		Id:                 file1Id,
		Name:               "zip_member_one.txt",
		Size:               "3 B",
		SizeBytes:          3,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ExpireAt:           2147483646,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		ContentType:        "text/plain",
		UserId:             999,
		BundleId:           bundle.Id,
	})
	file2Id := helper.GenerateRandomString(16)
	database.SaveMetaData(models.File{
		Id:                 file2Id,
		Name:               "zip_member_two.txt",
		Size:               "3 B",
		SizeBytes:          3,
		SHA1:               "c4f9375f9834b4e7f0a528cc65c055702bf5f24a",
		ExpireAt:           2147483646,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		ContentType:        "text/plain",
		UserId:             999,
		BundleId:           bundle.Id,
	})

	recipientId := database.SaveShareRecipient(models.ShareRecipient{
		Email:     "zip-ordering-recipient@example.com",
		CreatedAt: time.Now().Unix(),
	})
	// Grant exactly one bundle download, then immediately spend it, so the recipient's bundle
	// allowance is already exhausted by the time the request under test arrives.
	database.SetShareGrants(models.ShareResourceBundle, bundle.Id, []int{recipientId}, 999, 1)
	if !database.IncreaseShareGrantDownloadCount(models.ShareResourceBundle, bundle.Id, recipientId) {
		t.Fatalf("Failed to pre-exhaust the bundle allowance for the test fixture")
	}
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceBundle, bundle.Id)
		database.DeleteShareRecipient(recipientId)
		database.DeleteMetaData(file1Id)
		database.DeleteMetaData(file2Id)
		filebundle.Delete(bundle)
	})

	countsBefore := map[string]int{}
	for _, id := range []string{file1Id, file2Id} {
		file, ok := database.GetMetaDataById(id)
		if !ok {
			t.Fatalf("Fixture file %s vanished before the request", id)
		}
		countsBefore[id] = file.DownloadCount
	}

	cookie := testShareAccessCookie(models.ShareResourceBundle, bundle.Id, recipientId)
	client := &http.Client{}
	req, err := http.NewRequest("GET", "http://127.0.0.1:53843/pubapi/folderzip?id="+bundle.Id, nil)
	if err != nil {
		t.Fatalf("Failed to build request: %v", err)
	}
	req.Header.Set("Cookie", cookie.Name+"="+cookie.Value)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to request folderzip: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected /pubapi/folderzip to deny an exhausted bundle allowance as not found, got status %d", resp.StatusCode)
	}

	for _, id := range []string{file1Id, file2Id} {
		file, ok := database.GetMetaDataById(id)
		if !ok {
			t.Fatalf("Fixture file %s vanished after the request", id)
		}
		if file.DownloadCount != countsBefore[id] {
			t.Errorf("Expected DownloadCount for %s to stay at %d, got %d", id, countsBefore[id], file.DownloadCount)
		}
	}
}

// TestPublicApiConfig tests GET /pubapi/config for non-sensitive configuration values
func TestPublicApiConfig(t *testing.T) {
	t.Parallel()
	client := &http.Client{}
	resp, err := client.Get("http://127.0.0.1:53843/pubapi/config")
	if err != nil {
		t.Errorf("Failed to make request: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}

	// Verify the response contains the expected top-level fields
	if _, ok := response["publicName"]; !ok {
		t.Errorf("Missing publicName field")
	}

	// Verify auth section exists with boolean fields
	if auth, ok := response["auth"].(map[string]interface{}); !ok {
		t.Errorf("Missing or invalid auth field")
	} else {
		if _, ok := auth["internal"]; !ok {
			t.Errorf("Missing internal field in auth")
		}
		if _, ok := auth["oauth"]; !ok {
			t.Errorf("Missing oauth field in auth")
		}
		if _, ok := auth["oauthProvider"]; !ok {
			t.Errorf("Missing oauthProvider field in auth")
		}
	}

	// Verify features section exists with boolean fields
	if features, ok := response["features"].(map[string]interface{}); !ok {
		t.Errorf("Missing or invalid features field")
	} else {
		if _, ok := features["folders"]; !ok {
			t.Errorf("Missing folders field in features")
		}
		if _, ok := features["fileRequests"]; !ok {
			t.Errorf("Missing fileRequests field in features")
		}
		if _, ok := features["e2eEncryption"]; !ok {
			t.Errorf("Missing e2eEncryption field in features")
		}
		if _, ok := features["hotlinks"]; !ok {
			t.Errorf("Missing hotlinks field in features")
		}
	}

	// Verify limits section exists with numeric fields
	if limits, ok := response["limits"].(map[string]interface{}); !ok {
		t.Errorf("Missing or invalid limits field")
	} else {
		if _, ok := limits["maxFileSizeMB"]; !ok {
			t.Errorf("Missing maxFileSizeMB field in limits")
		}
		if _, ok := limits["chunkSizeMB"]; !ok {
			t.Errorf("Missing chunkSizeMB field in limits")
		}
		if _, ok := limits["maxParallelUploads"]; !ok {
			t.Errorf("Missing maxParallelUploads field in limits")
		}
		if _, ok := limits["minPasswordLength"]; !ok {
			t.Errorf("Missing minPasswordLength field in limits")
		}
		if _, ok := limits["maxExpirySeconds"]; !ok {
			t.Errorf("Missing maxExpirySeconds field in limits")
		}
		options, ok := limits["expiryOptionsSeconds"].([]interface{})
		if !ok {
			t.Errorf("Missing or invalid expiryOptionsSeconds field in limits")
		} else if len(options) == 0 {
			t.Errorf("expiryOptionsSeconds must never be empty")
		}
	}
}

// TestPublicApiConfigNoSensitiveFields verifies that sensitive configuration is not exposed
func TestPublicApiConfigNoSensitiveFields(t *testing.T) {
	t.Parallel()
	client := &http.Client{}
	resp, err := client.Get("http://127.0.0.1:53843/pubapi/config")
	if err != nil {
		t.Errorf("Failed to make request: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode response: %v", err)
		return
	}

	// Convert to JSON string to check it
	respBytes, err := json.Marshal(response)
	if err != nil {
		t.Errorf("Failed to marshal response: %v", err)
		return
	}
	respStr := strings.ToLower(string(respBytes))

	// Check for sensitive terms that should NOT be in the response
	sensitiveTerms := []string{"clientid", "secret", "bucket"}
	for _, term := range sensitiveTerms {
		if strings.Contains(respStr, term) {
			t.Errorf("Response should not contain sensitive term: %s", term)
		}
	}
}

// TestPublicApiConfigUnauthenticated verifies that the endpoint does not require authentication
func TestPublicApiConfigUnauthenticated(t *testing.T) {
	t.Parallel()
	// Create client without any authentication
	client := &http.Client{}
	resp, err := client.Get("http://127.0.0.1:53843/pubapi/config")
	if err != nil {
		t.Errorf("Failed to make request: %v", err)
		return
	}
	defer resp.Body.Close()

	// Should succeed without authentication
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 for unauthenticated request, got %d", resp.StatusCode)
	}
}

// TestFolderPasswordCrossMemberRejected tests that a password-protected folder requires
// the password to match ALL members, not just one. A bundle with two members having
// different passwords should reject a password that only matches one member.
func TestFolderPasswordCrossMemberRejected(t *testing.T) {
	t.Parallel()
	uniqueName := "TestFolderCrossPw_" + helper.GenerateRandomString(8)
	password1 := "password1"
	password2 := "different_password"

	bundle := filebundle.Create(uniqueName, 999)

	hash1 := configuration.HashPassword(password1, false, "")
	hash2 := configuration.HashPassword(password2, false, "")

	database.SaveMetaData(models.File{
		Id:                 "zzzzzzzzzzzzzzzz",
		Name:               "file1.txt",
		Size:               "10 B",
		SizeBytes:          10,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ExpireAt:           2147483646,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		ContentType:        "text/plain",
		UserId:             999,
		BundleId:           bundle.Id,
		PasswordHash:       hash1,
	})

	database.SaveMetaData(models.File{
		Id:                 "aaaaaaaaaaaaaaaa",
		Name:               "file2.txt",
		Size:               "10 B",
		SizeBytes:          10,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ExpireAt:           2147483646,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		ContentType:        "text/plain",
		UserId:             999,
		BundleId:           bundle.Id,
		PasswordHash:       hash2,
	})

	client := &http.Client{}

	payloadWrongPw := []byte(`{"password":"password1"}`)
	req, err := http.NewRequest("POST", "http://127.0.0.1:53843/pubapi/folderpassword?id="+bundle.Id, bytes.NewReader(payloadWrongPw))
	if err != nil {
		t.Errorf("Failed to create request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Errorf("Failed to make POST request: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode response: %v", err)
		return
	}

	if ok, exists := response["ok"].(bool); !exists || ok {
		t.Errorf("Expected ok=false, got %v", response["ok"])
	}

	if len(resp.Cookies()) > 0 {
		for _, cookie := range resp.Cookies() {
			if strings.HasPrefix(cookie.Name, "b") {
				t.Errorf("Expected no bundle cookie to be set, but got %s", cookie.Name)
			}
		}
	}

	bundleMatch := filebundle.Create("TestFolderMatchPw_"+helper.GenerateRandomString(8), 999)
	sharedHash := configuration.HashPassword("shared_password", false, "")

	database.SaveMetaData(models.File{
		Id:                 helper.GenerateRandomString(16),
		Name:               "file3.txt",
		Size:               "10 B",
		SizeBytes:          10,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ExpireAt:           2147483646,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		ContentType:        "text/plain",
		UserId:             999,
		BundleId:           bundleMatch.Id,
		PasswordHash:       sharedHash,
	})

	database.SaveMetaData(models.File{
		Id:                 helper.GenerateRandomString(16),
		Name:               "file4.txt",
		Size:               "10 B",
		SizeBytes:          10,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ExpireAt:           2147483646,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		ContentType:        "text/plain",
		UserId:             999,
		BundleId:           bundleMatch.Id,
		PasswordHash:       sharedHash,
	})

	payloadCorrectPw := []byte(`{"password":"shared_password"}`)
	req2, err := http.NewRequest("POST", "http://127.0.0.1:53843/pubapi/folderpassword?id="+bundleMatch.Id, bytes.NewReader(payloadCorrectPw))
	if err != nil {
		t.Errorf("Failed to create request: %v", err)
		return
	}
	req2.Header.Set("Content-Type", "application/json")

	resp2, err := client.Do(req2)
	if err != nil {
		t.Errorf("Failed to make POST request: %v", err)
		return
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp2.StatusCode)
	}

	var response2 map[string]interface{}
	if err := json.NewDecoder(resp2.Body).Decode(&response2); err != nil {
		t.Errorf("Failed to decode response: %v", err)
		return
	}

	if ok, exists := response2["ok"].(bool); !exists || !ok {
		t.Errorf("Expected ok=true, got %v", response2["ok"])
	}

	cookieFound := false
	for _, cookie := range resp2.Cookies() {
		if strings.HasPrefix(cookie.Name, "b") {
			cookieFound = true
			break
		}
	}
	if !cookieFound {
		t.Errorf("Expected bundle cookie to be set")
	}
}

// TestFolderLockedLeaksNothing tests that a password-protected folder without a valid cookie
// returns only id and requiresPassword fields, never name or files.
func TestFolderLockedLeaksNothing(t *testing.T) {
	t.Parallel()
	uniqueName := "TestFolderLocked_" + helper.GenerateRandomString(8)
	password := "secret_password"

	bundle := filebundle.Create(uniqueName, 999)

	pwHash := configuration.HashPassword(password, false, "")

	database.SaveMetaData(models.File{
		Id:                 helper.GenerateRandomString(16),
		Name:               "sensitive.txt",
		Size:               "10 B",
		SizeBytes:          10,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ExpireAt:           2147483646,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		ContentType:        "text/plain",
		UserId:             999,
		BundleId:           bundle.Id,
		PasswordHash:       pwHash,
	})

	client := &http.Client{}
	resp, err := client.Get("http://127.0.0.1:53843/pubapi/folder?id=" + bundle.Id)
	if err != nil {
		t.Errorf("Failed to make request: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode response: %v", err)
		return
	}

	if id, ok := response["id"]; !ok || id != bundle.Id {
		t.Errorf("Expected id '%s', got %v", bundle.Id, id)
	}

	if requiresPw, ok := response["requiresPassword"].(bool); !ok || !requiresPw {
		t.Errorf("Expected requiresPassword=true, got %v", response["requiresPassword"])
	}

	if _, ok := response["name"]; ok {
		t.Errorf("Expected name to be absent when locked, but it was present: %v", response["name"])
	}

	if _, ok := response["files"]; ok {
		t.Errorf("Expected files to be absent when locked, but it was present: %v", response["files"])
	}
}

// TestPublicApiFolderDeadMembersLeaksNothing is a regression test for bug 1: pubApiFolder
// returned 200 with `"name": bundle.Name` even when its only member had expired, because
// isProtected was computed by scanning the (now empty) servable-member list rather than the
// bundle's true membership - a password-protected folder whose members had all expired
// therefore reported requiresPassword: false and handed back its name with no password
// prompt at all, in the exact situation the sibling pubApiFolderZip already refused as 404.
// This asserts a dead folder's name never appears anywhere in the response, and that a
// protected-but-dead folder does not report requiresPassword: false.
func TestPublicApiFolderDeadMembersLeaksNothing(t *testing.T) {
	t.Parallel()

	// Case 1: an unprotected folder whose only member has already expired.
	uniqueName := "TestFolderDead_" + helper.GenerateRandomString(8)
	bundle := filebundle.Create(uniqueName, 999)
	database.SaveMetaData(models.File{
		Id:                 helper.GenerateRandomString(16),
		Name:               "dead_unprotected.txt",
		Size:               "10 B",
		SizeBytes:          10,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ExpireAt:           time.Now().Add(-1 * time.Hour).Unix(), // already expired
		UnlimitedDownloads: true,
		UnlimitedTime:      false,
		ContentType:        "text/plain",
		UserId:             999,
		BundleId:           bundle.Id,
	})

	client := &http.Client{}
	resp, err := client.Get("http://127.0.0.1:53843/pubapi/folder?id=" + bundle.Id)
	if err != nil {
		t.Fatalf("Failed to request dead folder: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if strings.Contains(string(body), uniqueName) {
		t.Errorf("Dead folder's name leaked into the response: %s", body)
	}
	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err == nil {
		if _, ok := response["name"]; ok {
			t.Errorf("Expected no 'name' field anywhere in the response for a dead folder, got: %s", body)
		}
	}

	// Case 2: a folder whose only member is BOTH password protected AND already expired -
	// the case that used to skip the password gate entirely (isProtected computed as false
	// from an empty servable-member scan) and hand back the name unlocked.
	protectedName := "TestFolderDeadProtected_" + helper.GenerateRandomString(8)
	protectedBundle := filebundle.Create(protectedName, 999)
	pwHash := configuration.HashPassword("dead_secret_password", false, "")
	database.SaveMetaData(models.File{
		Id:                 helper.GenerateRandomString(16),
		Name:               "dead_protected.txt",
		Size:               "10 B",
		SizeBytes:          10,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ExpireAt:           time.Now().Add(-1 * time.Hour).Unix(), // already expired
		UnlimitedDownloads: true,
		UnlimitedTime:      false,
		ContentType:        "text/plain",
		UserId:             999,
		BundleId:           protectedBundle.Id,
		PasswordHash:       pwHash,
	})

	resp2, err := client.Get("http://127.0.0.1:53843/pubapi/folder?id=" + protectedBundle.Id)
	if err != nil {
		t.Fatalf("Failed to request dead protected folder: %v", err)
	}
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)

	if strings.Contains(string(body2), protectedName) {
		t.Errorf("Dead protected folder's name leaked into the response: %s", body2)
	}
	var response2 map[string]interface{}
	if err := json.Unmarshal(body2, &response2); err == nil {
		if _, ok := response2["name"]; ok {
			t.Errorf("Expected no 'name' field anywhere in the response for a dead protected folder, got: %s", body2)
		}
		if requiresPw, ok := response2["requiresPassword"]; ok && requiresPw == false {
			t.Errorf("Expected no requiresPassword:false leak for a folder that was actually protected, got: %s", body2)
		}
	}
}

// TestFolderZipCounterEnforced tests that the download counter is enforced by pubApiFolderZip,
// and - since the no-partial-archive fix - that a member becoming exhausted between two
// requests now refuses the whole second request rather than silently serving a zip with that
// member dropped. The bundle deliberately has TWO members and the request omits ids=, so
// control cannot take the single-file serveBundleFile shortcut (len(requestedMembers) == 1).
// A previous version of this test asserted the second request still succeeded with the
// exhausted member silently excluded from the archive; that was exactly bug 2 (a folder zip
// silently omitting an unservable member), inverted here to assert the fix instead.
func TestFolderZipCounterEnforced(t *testing.T) {
	t.Parallel()
	uniqueName := "TestFolderCounter_" + helper.GenerateRandomString(8)

	bundle := filebundle.Create(uniqueName, 999)

	limitedId := helper.GenerateRandomString(16)
	database.SaveMetaData(models.File{
		Id:                 limitedId,
		Name:               "limited.txt",
		Size:               "10 B",
		SizeBytes:          10,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ExpireAt:           2147483646,
		UnlimitedDownloads: false,
		DownloadsRemaining: 1,
		UnlimitedTime:      true,
		ContentType:        "text/plain",
		UserId:             999,
		BundleId:           bundle.Id,
	})

	unlimitedId := helper.GenerateRandomString(16)
	database.SaveMetaData(models.File{
		Id:                 unlimitedId,
		Name:               "unlimited.txt",
		Size:               "10 B",
		SizeBytes:          10,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ExpireAt:           2147483646,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		ContentType:        "text/plain",
		UserId:             999,
		BundleId:           bundle.Id,
	})

	client := &http.Client{}

	// No ids= parameter: both members are requested, so len(filesToServe) == 2 and control must
	// go through the multi-member zip path and its metering loop.
	firstReq, err := http.NewRequest("GET", "http://127.0.0.1:53843/pubapi/folderzip?id="+bundle.Id, nil)
	if err != nil {
		t.Errorf("Failed to create first request: %v", err)
		return
	}

	resp1, err := client.Do(firstReq)
	if err != nil {
		t.Errorf("Failed to make first request: %v", err)
		return
	}
	resp1.Body.Close()

	if resp1.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 for first download, got %d", resp1.StatusCode)
	}
	if contentType := resp1.Header.Get("Content-Type"); contentType != "application/zip" {
		t.Errorf("Expected a zip response for a two-member bundle, got Content-Type %s", contentType)
	}
	if remaining := database.GetDownloadsRemaining(limitedId); remaining != 0 {
		t.Errorf("Expected the metering loop to consume the limited member's allowance, got %d remaining", remaining)
	}

	// Second request: the limited member's allowance is now exhausted. The bundle can no
	// longer be served as a complete unit - with per-file counters still in place, a bundle
	// is only servable if every member is - so the whole request must be refused rather than
	// silently handing back a zip with the exhausted member dropped, and no zip body must be
	// sent.
	secondReq, err := http.NewRequest("GET", "http://127.0.0.1:53843/pubapi/folderzip?id="+bundle.Id, nil)
	if err != nil {
		t.Errorf("Failed to create second request: %v", err)
		return
	}

	resp2, err := client.Do(secondReq)
	if err != nil {
		t.Errorf("Failed to make second request: %v", err)
		return
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()

	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404 refusing the whole request once a member is exhausted, got %d", resp2.StatusCode)
	}
	if contentType := resp2.Header.Get("Content-Type"); contentType == "application/zip" {
		t.Errorf("Expected no archive body once a member is exhausted, got a zip response: %s", body2)
	}
	if remaining := database.GetDownloadsRemaining(limitedId); remaining != 0 {
		t.Errorf("Exhausted member's allowance must not go negative or be re-consumed, got %d remaining", remaining)
	}
	if unlimitedCount := mustGetMetaData(t, unlimitedId).DownloadCount; unlimitedCount != 1 {
		t.Errorf("Expected the unlimited member's DownloadCount to stay at 1 from the first request (refusal must not touch it), got %d", unlimitedCount)
	}
}

// mustGetMetaData is a small test helper that fetches a file's metadata or fails the test.
func mustGetMetaData(t *testing.T, id string) models.File {
	t.Helper()
	file, ok := database.GetMetaDataById(id)
	if !ok {
		t.Fatalf("Fixture file %s vanished", id)
	}
	return file
}

// TestFolderZipThreeMembersTwoExhaustedRefusesWhole is a regression test for the second half
// of bug 2: servableBundleMembers used storage.IsExpiredFile, which counts
// DownloadsRemaining < 1 as expired, to build the member list itself - so a 3-member bundle
// with 2 exhausted members silently narrowed down to a set of one before pubApiFolderZip ever
// decided how to serve it, and len(filesToServe) == 1 then took the raw-single-file shortcut
// instead of a zip, serving the wrong member as if it were the only thing ever in the bundle.
// This asserts the request omits ids= (so the shortcut cannot be legitimised by an explicit
// single id) and is refused as a whole - no archive, and specifically not served as a bare
// single file.
func TestFolderZipThreeMembersTwoExhaustedRefusesWhole(t *testing.T) {
	t.Parallel()
	uniqueName := "TestFolderThreeTwoExhausted_" + helper.GenerateRandomString(8)
	bundle := filebundle.Create(uniqueName, 999)

	liveId := helper.GenerateRandomString(16)
	database.SaveMetaData(models.File{
		Id:                 liveId,
		Name:               "still_live.txt",
		Size:               "10 B",
		SizeBytes:          10,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ExpireAt:           2147483646,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		ContentType:        "text/plain",
		UserId:             999,
		BundleId:           bundle.Id,
	})

	exhaustedId1 := helper.GenerateRandomString(16)
	database.SaveMetaData(models.File{
		Id:                 exhaustedId1,
		Name:               "exhausted_one.txt",
		Size:               "10 B",
		SizeBytes:          10,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ExpireAt:           2147483646,
		UnlimitedDownloads: false,
		DownloadsRemaining: 0,
		UnlimitedTime:      true,
		ContentType:        "text/plain",
		UserId:             999,
		BundleId:           bundle.Id,
	})

	exhaustedId2 := helper.GenerateRandomString(16)
	database.SaveMetaData(models.File{
		Id:                 exhaustedId2,
		Name:               "exhausted_two.txt",
		Size:               "10 B",
		SizeBytes:          10,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ExpireAt:           2147483646,
		UnlimitedDownloads: false,
		DownloadsRemaining: 0,
		UnlimitedTime:      true,
		ContentType:        "text/plain",
		UserId:             999,
		BundleId:           bundle.Id,
	})

	t.Cleanup(func() {
		database.DeleteMetaData(liveId)
		database.DeleteMetaData(exhaustedId1)
		database.DeleteMetaData(exhaustedId2)
		filebundle.Delete(bundle)
	})

	client := &http.Client{}
	resp, err := client.Get("http://127.0.0.1:53843/pubapi/folderzip?id=" + bundle.Id)
	if err != nil {
		t.Fatalf("Failed to request folderzip: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusOK {
		t.Errorf("Expected the whole request to be refused when 2 of 3 members are exhausted, got 200: %s", body)
	}
	if contentType := resp.Header.Get("Content-Type"); contentType == "text/plain" {
		t.Errorf("Expected no raw single-file response - that would mean exhaustion-based filtering silently picked a lone survivor - got Content-Type text/plain, body: %s", body)
	}
	if contentType := resp.Header.Get("Content-Type"); contentType == "application/zip" {
		t.Errorf("Expected no archive body when not every requested member is servable, got a zip response")
	}
}

// TestFolderZipRaceWindowRefusesWhole forces the exact interleaving pubApiFolderZip's own
// comments describe but TestFolderZipCounterEnforced and
// TestFolderZipThreeMembersTwoExhaustedRefusesWhole above can only hit by chance under
// contention: a member that becomes exhausted in the window between the upfront availability
// check and the metering loop that re-checks and consumes each member, both inside a single
// request. It uses ids= to fix processing order (member order is otherwise map-derived and not
// deterministic) and the folderZipRaceHooks test seam to run the exhausting write at the exact
// instant the metering loop reaches the second member, simulating a second, concurrent download
// of that member landing in that window. This hits the race window on every run instead of only
// under load, and asserts the fix: the whole request is refused rather than the archive silently
// narrowing to just the first member.
func TestFolderZipRaceWindowRefusesWhole(t *testing.T) {
	t.Parallel()
	uniqueName := "TestFolderRaceWindow_" + helper.GenerateRandomString(8)
	bundle := filebundle.Create(uniqueName, 999)

	firstId := helper.GenerateRandomString(16)
	database.SaveMetaData(models.File{
		Id:                 firstId,
		Name:               "first.txt",
		Size:               "10 B",
		SizeBytes:          10,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ExpireAt:           2147483646,
		UnlimitedDownloads: false,
		DownloadsRemaining: 5,
		UnlimitedTime:      true,
		ContentType:        "text/plain",
		UserId:             999,
		BundleId:           bundle.Id,
	})

	racedId := helper.GenerateRandomString(16)
	database.SaveMetaData(models.File{
		Id:                 racedId,
		Name:               "raced.txt",
		Size:               "10 B",
		SizeBytes:          10,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ExpireAt:           2147483646,
		UnlimitedDownloads: false,
		DownloadsRemaining: 1,
		UnlimitedTime:      true,
		ContentType:        "text/plain",
		UserId:             999,
		BundleId:           bundle.Id,
	})

	t.Cleanup(func() {
		database.DeleteMetaData(firstId)
		database.DeleteMetaData(racedId)
		filebundle.Delete(bundle)
	})

	// Registers the race: fires the instant the metering loop reaches racedId, consuming its
	// only remaining download out from under it - exactly what a second, concurrent request for
	// the same file would do if it won that race in production. LoadAndDelete makes this
	// one-shot, and it is keyed by racedId's own random id, so it cannot affect any other test's
	// bundle running in parallel.
	folderZipRaceHooks.Store(racedId, func() {
		if !database.IncreaseDownloadCount(racedId, true) {
			t.Errorf("Race setup failed: expected to be able to consume racedId's only download")
		}
	})
	t.Cleanup(func() { folderZipRaceHooks.Delete(racedId) })

	client := &http.Client{}
	resp, err := client.Get("http://127.0.0.1:53843/pubapi/folderzip?id=" + bundle.Id + "&ids=" + firstId + "," + racedId)
	if err != nil {
		t.Fatalf("Failed to request folderzip: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected the whole request refused once the race window exhausts a member mid-loop, got %d: %s", resp.StatusCode, body)
	}
	if contentType := resp.Header.Get("Content-Type"); contentType == "application/zip" {
		t.Errorf("Expected no archive body once a member is exhausted mid-loop, got a zip response")
	}
	// firstId is processed before racedId (ids= fixes the order) and is therefore already
	// atomically decremented by the time racedId's failure refuses the request. This is the
	// accepted, documented cost in pubApiFolderZip: there is no re-increment primitive to undo
	// it with.
	if remaining := database.GetDownloadsRemaining(firstId); remaining != 4 {
		t.Errorf("Expected firstId's allowance to be spent by the metering loop before the refusal, got %d remaining, want 4", remaining)
	}
	if remaining := database.GetDownloadsRemaining(racedId); remaining != 0 {
		t.Errorf("Expected racedId's allowance to stay at 0 (not go negative), got %d remaining", remaining)
	}
}

// TestFolderZipMembershipAndFileRequestExclusion tests membership validation and file request exclusion.
// (a) ids containing a file from a different bundle returns 400
// (b) Files with UploadRequestId set are excluded from /pubapi/folder and /pubapi/folderzip
func TestFolderZipMembershipAndFileRequestExclusion(t *testing.T) {
	t.Parallel()
	bundle1 := filebundle.Create("TestFolderZipMembership_"+helper.GenerateRandomString(8), 999)
	bundle2 := filebundle.Create("TestFolderZipOther_"+helper.GenerateRandomString(8), 999)

	file1Id := helper.GenerateRandomString(16)
	file2Id := helper.GenerateRandomString(16)
	fileRequestId := helper.GenerateRandomString(16)

	database.SaveMetaData(models.File{
		Id:                 file1Id,
		Name:               "file1.txt",
		Size:               "10 B",
		SizeBytes:          10,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ExpireAt:           2147483646,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		ContentType:        "text/plain",
		UserId:             999,
		BundleId:           bundle1.Id,
	})

	database.SaveMetaData(models.File{
		Id:                 file2Id,
		Name:               "file2_other_bundle.txt",
		Size:               "10 B",
		SizeBytes:          10,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ExpireAt:           2147483646,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		ContentType:        "text/plain",
		UserId:             999,
		BundleId:           bundle2.Id,
	})

	database.SaveMetaData(models.File{
		Id:                 fileRequestId,
		Name:               "file_request_upload.txt",
		Size:               "10 B",
		SizeBytes:          10,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ExpireAt:           2147483646,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		ContentType:        "text/plain",
		UserId:             999,
		BundleId:           bundle1.Id,
		UploadRequestId:    "some_request_id",
	})

	client := &http.Client{}

	resp1, err := client.Get("http://127.0.0.1:53843/pubapi/folderzip?id=" + bundle1.Id + "&ids=" + file1Id + "," + file2Id)
	if err != nil {
		t.Errorf("Failed to make request with cross-bundle ids: %v", err)
		return
	}
	resp1.Body.Close()

	if resp1.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400 for cross-bundle ids, got %d", resp1.StatusCode)
	}

	resp2, err := client.Get("http://127.0.0.1:53843/pubapi/folder?id=" + bundle1.Id)
	if err != nil {
		t.Errorf("Failed to make folder request: %v", err)
		return
	}
	defer resp2.Body.Close()

	var folderResponse map[string]interface{}
	if err := json.NewDecoder(resp2.Body).Decode(&folderResponse); err != nil {
		t.Errorf("Failed to decode folder response: %v", err)
		return
	}

	files, ok := folderResponse["files"].([]interface{})
	if !ok {
		t.Errorf("Expected files array in response")
		return
	}

	if len(files) != 1 {
		t.Errorf("Expected 1 file (file request should be excluded), got %d files", len(files))
	}

	resp3, err := client.Get("http://127.0.0.1:53843/pubapi/folderzip?id=" + bundle1.Id)
	if err != nil {
		t.Errorf("Failed to make folderzip request: %v", err)
		return
	}
	defer resp3.Body.Close()

	// With the file-request member correctly excluded, bundle1 has exactly one servable member
	// (file1.txt), so the handler must serve it directly as a raw file rather than a zip. The
	// previous version of this test asserted the opposite - that the response was a zip, which
	// can only happen if the excluded file-request member was actually included - i.e. it
	// asserted the vulnerable behaviour instead of the fix.
	if contentType := resp3.Header.Get("Content-Type"); contentType != "text/plain" {
		t.Errorf("Expected a raw single-file response with Content-Type text/plain, got %s", contentType)
	}

	// The Content-Disposition filename must name the single remaining servable member
	// (file1.txt), and must never reference the excluded file-request member: this is what
	// proves the file-request member's bytes were not served.
	disposition := resp3.Header.Get("Content-Disposition")
	if !strings.Contains(disposition, `filename="file1.txt"`) {
		t.Errorf("Expected the single remaining member (file1.txt) to be served, got Content-Disposition %q", disposition)
	}
	if strings.Contains(disposition, "file_request_upload.txt") {
		t.Errorf("File-request member must not be served, but Content-Disposition referenced it: %q", disposition)
	}
}

// routePattern resolves the registered pattern for a request path, or "" for no match.
// Asserting on mux.Handler rather than on live responses keeps the check about
// registration itself: a route that is not registered cannot be reached by any method,
// header trick or auth state, which is the guarantee GOKAPI_DISABLE_BUILTIN_UI exists for.
// The one exception is "/", which stays registered as a liveness endpoint; paths that
// fall through to it are asserted on their response code instead.
func routePattern(mux *http.ServeMux, path string) string {
	_, pattern := mux.Handler(httptest.NewRequest("GET", path, nil))
	return pattern
}

func TestCreateMuxDisableBuiltinUi(t *testing.T) {
	webserverDir, _ := fs.Sub(staticFolderEmbedded, "web/static")

	// Endpoints the standalone SPA and API clients call, keyed by a request path that
	// must resolve to them. These must survive disabling the built-in UI. The oauth
	// routes are absent here only because the test configuration uses internal auth,
	// under which they are never registered in either mode.
	requiredRoutes := map[string]string{
		"/api/auth/create":       "/api/",
		"/auth/token":            "/auth/token",
		"/login":                 "/login",
		"/logout":                "/logout",
		"/error":                 "/error",
		"/downloadFile":          "/downloadFile",
		"/downloadPresigned":     "/downloadPresigned",
		"/uploadChunk":           "/uploadChunk",
		"/uploadStatus":          "/uploadStatus",
		"/main.wasm":             "/main.wasm",
		"/e2e.wasm":              "/e2e.wasm",
		"/pubapi/config":         "/pubapi/config",
		"/pubapi/file":           "/pubapi/file",
		"/pubapi/filepassword":   "/pubapi/filepassword",
		"/pubapi/folder":         "/pubapi/folder",
		"/pubapi/folderpassword": "/pubapi/folderpassword",
		"/pubapi/folderzip":      "/pubapi/folderzip",
		"/pubapi/uploadrequest":  "/pubapi/uploadrequest",
		"/pubapi/share/resend":   "/pubapi/share/resend",
	}
	// The stock UI surface, including the anonymous download doors, keyed the same way
	uiRoutes := map[string]string{
		"/admin":              "/admin",
		"/apiKeys":            "/apiKeys",
		"/users":              "/users",
		"/logs":               "/logs",
		"/filerequests":       "/filerequests",
		"/e2eSetup":           "/e2eSetup",
		"/index":              "/index",
		"/forgotpw":           "/forgotpw",
		"/changePassword":     "/changePassword",
		"/publicUpload":       "/publicUpload",
		"/d":                  "/d",
		"/h/someid":           "/h/",
		"/hotlink/someid":     "/hotlink/",
		"/d/someid/file.txt":  "/d/{id}/{filename}",
		"/dh/someid/file.txt": "/dh/{id}/{filename}",
	}

	muxDefault := createMux(webserverDir, false)
	muxNoUi := createMux(webserverDir, true)

	for path, expected := range requiredRoutes {
		test.IsEqualString(t, routePattern(muxDefault, path), expected)
		test.IsEqualString(t, routePattern(muxNoUi, path), expected)
	}
	// "/" is the one stock path that stays registered with the UI off: the container
	// HEALTHCHECK probes it, so it answers a plain-text OK. It must never serve the
	// stock static assets.
	test.IsEqualString(t, routePattern(muxDefault, "/"), "/")
	test.IsEqualString(t, routePattern(muxNoUi, "/"), "/")
	rootRec := httptest.NewRecorder()
	muxNoUi.ServeHTTP(rootRec, httptest.NewRequest("GET", "/", nil))
	test.IsEqualInt(t, rootRec.Code, http.StatusOK)
	test.IsEqualString(t, strings.TrimSpace(rootRec.Body.String()), "OK")

	for path, expected := range uiRoutes {
		test.IsEqualString(t, routePattern(muxDefault, path), expected)
		// With the UI off these paths no longer have a route of their own. Go's
		// ServeMux funnels every unclaimed path to the "/" pattern, so registering the
		// liveness endpoint means the assertion has to be behavioural rather than about
		// registration: the handler refuses anything that is not exactly "/", so these
		// must answer 404 and can never serve a stock page.
		test.IsEqualString(t, routePattern(muxNoUi, path), "/")
		rec := httptest.NewRecorder()
		muxNoUi.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		test.IsEqualInt(t, rec.Code, http.StatusNotFound)
	}
}
