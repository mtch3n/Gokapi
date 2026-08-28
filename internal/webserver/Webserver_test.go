//go:build !integration && test

package webserver

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
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
	resp, err := client.Get("http://127.0.0.1:53843/pubapi/uploadrequest?id=testuploadreq123456&key=testkey123")
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
	resp, err := client.Get("http://127.0.0.1:53843/pubapi/uploadrequest?id=expireduploadreq1234&key=expiredkey123")
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
	resp, err := client.Get("http://127.0.0.1:53843/pubapi/uploadrequest?id=testuploadreqkey1234&key=wrongkey")
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

// TestFolderZipCounterEnforced tests that the download counter is enforced by the multi-member
// zip metering loop in pubApiFolderZip. The bundle deliberately has TWO servable members and the
// request omits ids=, so control cannot take the single-file serveBundleFile shortcut
// (len(filesToServe) == 1) and must go through the metering loop the counter protects. A
// previous version of this test used a single-member bundle plus an explicit ids=, which took
// serveBundleFile and never exercised the metering loop at all.
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

	// Second request: the limited member's allowance is now exhausted, so the metering loop must
	// exclude it from the zip rather than fail the whole request - the unlimited member is still
	// servable, so this must still succeed, and the exhausted member's allowance must not go
	// negative or be re-consumed.
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
	resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 for second download (unlimited member still servable), got %d", resp2.StatusCode)
	}
	if remaining := database.GetDownloadsRemaining(limitedId); remaining != 0 {
		t.Errorf("Exhausted member's allowance must not go negative or be re-consumed, got %d remaining", remaining)
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
