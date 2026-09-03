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
	"sync"
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/logging"
	gokapimail "github.com/forceu/gokapi/internal/mail"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/shareaccess"
	"github.com/forceu/gokapi/internal/storage/chunking/chunkreservation"
	"github.com/forceu/gokapi/internal/storage/filebundle"
	"github.com/forceu/gokapi/internal/storage/processingstatus"
	"github.com/forceu/gokapi/internal/test"
	"github.com/forceu/gokapi/internal/test/testconfiguration"
	"github.com/forceu/gokapi/internal/webserver/authentication"
	"github.com/forceu/gokapi/internal/webserver/authentication/csrftoken"
	"github.com/forceu/gokapi/internal/webserver/authentication/oauth"
	"github.com/forceu/gokapi/internal/webserver/ratelimiter"
)

// The test webserver of this package binds test.PortDefault, which moves with
// GOKAPI_TEST_PORT_OFFSET. Every URL below is built from the very port the listener binds, so the
// two can never drift apart.
var (
	urlIp        = test.Url(test.PortDefault)
	urlLocalhost = test.UrlLocalhost(test.PortDefault)
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
		Url:             urlLocalhost + "/",
		RequiredContent: []string{"<html><head><meta http-equiv=\"Refresh\" content=\"0; URL=./index\"></head></html>"},
		IsHtml:          true,
	})
}
func TestIndexFile(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             urlLocalhost + "/index",
		RequiredContent: []string{configuration.Get().RedirectUrl},
		IsHtml:          true,
	})
}
func TestStaticDirs(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             urlLocalhost + "/css/cover.css",
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
	loginUrl := urlLocalhost + "/login"

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

// TestShowLoginSetsForceConsentCookieInHybridMode verifies that logout redirects to
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

// TestAdminHybridResetPasswordGate verifies the guard in requireLogin that
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
		Url:             urlLocalhost + "/admin",
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
		Url:         urlLocalhost + "/admin",
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
		Url:         urlLocalhost + "/admin",
		RedirectUrl: "login",
	})
}
func TestAdminAuth(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             urlLocalhost + "/admin",
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
		Url:         urlLocalhost + "/admin",
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
		Url:             urlLocalhost + "/admin",
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
		Url:             urlLocalhost + "/admin",
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
		Url:         urlLocalhost + "/admin",
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
		Url:                urlLocalhost + "/d?id=123",
		IgnoreRedirectParm: true,
		RedirectUrl:        "error",
	})
}

// TestInvalidLinkIsAudited asserts that an unknown-id probe against a public download link (the
// most common denial case, and an enumeration signal worth recording) must produce a "denied"
// audit entry, not just the redirect.
func TestInvalidLinkIsAudited(t *testing.T) {
	t.Parallel()
	const unknownId = "doesNotExistW7auditCoverageTest"
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:                urlLocalhost + "/d?id=" + unknownId,
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
		Url:             urlLocalhost + "/error",
		RequiredContent: []string{"The link may have expired or the file has been downloaded too many times"},
		IsHtml:          true,
	})
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             urlLocalhost + "/error?e2e",
		RequiredContent: []string{"This file is encrypted, but no key was provided"},
		IsHtml:          true,
	})
}

func TestForgotPw(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             urlLocalhost + "/forgotpw",
		RequiredContent: []string{"--reconfigure"},
		IsHtml:          true,
	})
}

func TestLoginCorrect(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:         urlLocalhost + "/login",
		RedirectUrl: "admin",
		Method:      "POST",
		PostValues:  []test.PostBody{{"username", "test"}, {"password", "adminadmin"}, {"csrf-token", csrftoken.Generate(csrftoken.TypeLogin)}},
	})
}

func TestLoginIncorrectPassword(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             urlLocalhost + "/login",
		RequiredContent: []string{"Incorrect username or password"},
		IsHtml:          true,
		Method:          "POST",
		PostValues:      []test.PostBody{{"username", "test"}, {"password", "incorrect"}, {"csrf-token", csrftoken.Generate(csrftoken.TypeLogin)}},
	})
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             urlLocalhost + "/login",
		RequiredContent: []string{"The login page was open too long and expired. Please try again."},
		IsHtml:          true,
		Method:          "POST",
		PostValues:      []test.PostBody{{"username", "test"}, {"password", "incorrect"}, {"csrf-token", "incorrect"}},
	})
}
func TestLoginIncorrectUsername(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             urlLocalhost + "/login",
		RequiredContent: []string{"Incorrect username or password"},
		IsHtml:          true,
		Method:          "POST",
		PostValues:      []test.PostBody{{"username", "incorrect"}, {"password", "incorrect"}, {"csrf-token", csrftoken.Generate(csrftoken.TypeLogin)}},
	})
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             urlLocalhost + "/login",
		RequiredContent: []string{"The login page was open too long and expired. Please try again."},
		IsHtml:          true,
		Method:          "POST",
		PostValues:      []test.PostBody{{"username", "incorrect"}, {"password", "incorrect"}, {"csrf-token", "incorrect"}},
	})
}

func TestLogout(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             urlLocalhost + "/admin",
		RequiredContent: []string{"Downloads remaining"},
		IsHtml:          true,
		Cookies: []test.Cookie{{
			Name:  "session_token",
			Value: "logoutsession",
		}},
	})
	// Logout
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:         urlLocalhost + "/logout",
		RedirectUrl: "login",
		Cookies: []test.Cookie{{
			Name:  "session_token",
			Value: "logoutsession",
		}},
	})
	// Admin after logout
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:         urlLocalhost + "/admin",
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
		Url:             urlIp + "/hotlink/PhSs6mFtf8O5YGlLMfNw9rYXx9XRNkzCnJZpQBi7inunv3Z4A.jpg",
		RequiredContent: []string{"123"},
	})
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             urlIp + "/h/wjqlzpq2.jpg",
		RequiredContent: []string{"123"},
	})
	// Download expired hotlink
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             urlIp + "/hotlink/PhSs6mFtf8O5YGlLMfNw9rYXx9XRNkzCnJZpQBi7inunv3Z4A.jpg",
		RequiredContent: []string{"The requested file has expired"},
	})
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             urlIp + "/h/wjqlzpq2.jpg",
		RequiredContent: []string{"The requested file has expired"},
	})
}

func TestDownloadNoPassword(t *testing.T) {
	t.Parallel()
	// Show download page
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             urlIp + "/d?id=Wzol7LyY2QVczXynJtVo",
		IsHtml:          true,
		RequiredContent: []string{"smallfile2", "Retention period"}, // checks the retention-period notice is shown
	})
	// Download
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             urlIp + "/downloadFile?id=Wzol7LyY2QVczXynJtVo",
		RequiredContent: []string{"789"},
	})
	// Show download page expired file
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:                urlIp + "/d?id=Wzol7LyY2QVczXynJtVo",
		IgnoreRedirectParm: true,
		RedirectUrl:        "error",
	})
	// Download expired file
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:                urlIp + "/downloadFile?id=Wzol7LyY2QVczXynJtVo",
		IgnoreRedirectParm: true,
		RedirectUrl:        "error",
	})
}

func TestDownloadPagePassword(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             urlIp + "/d?id=jpLXGJKigM4hjtA6T6sN",
		IsHtml:          true,
		RequiredContent: []string{"Password required", "Retention period"}, // checks the retention-period notice is shown
	})
}
func TestDownloadPageIncorrectPassword(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             urlIp + "/d?id=jpLXGJKigM4hjtA6T6sN",
		IsHtml:          true,
		RequiredContent: []string{"Incorrect password!"},
		Method:          "POST",
		PostValues:      []test.PostBody{{"password", "incorrect"}},
	})
}

func TestDownloadIncorrectPasswordCookie(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             urlIp + "/d?id=jpLXGJKigM4hjtA6T6sN",
		IsHtml:          true,
		RequiredContent: []string{"Password required"},
		Cookies:         []test.Cookie{{"pjpLXGJKigM4hjtA6T6sN", "invalid"}},
	})
}

func TestDownloadIncorrectPassword(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:         urlIp + "/downloadFile?id=jpLXGJKigM4hjtA6T6sN",
		RedirectUrl: "d?id=jpLXGJKigM4hjtA6T6sN",
		Cookies:     []test.Cookie{{"pjpLXGJKigM4hjtA6T6sN", "invalid"}},
	})
}

func TestDownloadCorrectPassword(t *testing.T) {
	t.Parallel()
	// Submit download page correct password
	cookies := test.HttpPageResult(t, test.HttpTestConfig{
		Url:         urlIp + "/d?id=jpLXGJKigM4hjtA6T6sN2",
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
		Url:             urlIp + "/d?id=jpLXGJKigM4hjtA6T6sN2",
		IsHtml:          true,
		RequiredContent: []string{"smallfile"},
		Cookies:         []test.Cookie{{"pjpLXGJKigM4hjtA6T6sN2", pwCookie}},
	})
	// Download correct password
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             urlIp + "/downloadFile?id=jpLXGJKigM4hjtA6T6sN2",
		RequiredContent: []string{"456"},
		Cookies:         []test.Cookie{{"pjpLXGJKigM4hjtA6T6sN2", pwCookie}},
	})
}

func TestPostUploadNoAuth(t *testing.T) {
	t.Parallel()
	test.HttpPostUploadRequest(t, test.HttpTestConfig{
		Url:             urlIp + "/uploadChunk",
		UploadFileName:  "test/fileupload.jpg",
		ResultCode:      http.StatusUnauthorized,
		UploadFieldName: "file",

		RequiredContent: []string{"{\"Result\":\"error\",\"ErrorMessage\":\"Not authenticated\"}"},
	})
}

func TestPostUpload(t *testing.T) {
	// Open the SSE connection
	req, err := http.NewRequest("GET", urlIp+"/uploadStatus", nil)
	test.IsNil(t, err)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cookie", "session_token=validsession")

	resp, err := http.DefaultClient.Do(req)
	test.IsNil(t, err)
	defer resp.Body.Close()

	test.IsEqualInt(t, resp.StatusCode, http.StatusOK)
	scanner := bufio.NewScanner(resp.Body)

	test.HttpPostUploadRequest(t, test.HttpTestConfig{
		Url:             urlIp + "/uploadChunk",
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
			Url: urlIp + "/api/chunk/complete",
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
		Url:             urlIp + "/apiKeys",
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
		Url:             urlIp + "/apiKeys",
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
		Url:             urlIp + "/api/files/list",
		RequiredContent: []string{`{"Result":"error","ErrorMessage":"Unauthorized","ErrorCode":2}`},
		ExcludedContent: []string{"smallfile2"},
		ResultCode:      401,
		Cookies: []test.Cookie{{
			Name:  "session_token",
			Value: "invalid",
		}},
	})
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             urlIp + "/api/files/list",
		RequiredContent: []string{`{"Result":"error","ErrorMessage":"Unauthorized","ErrorCode":2}`},
		ExcludedContent: []string{"smallfile2"},
		ResultCode:      401,
		Headers:         []test.Header{{"apikey", "invalid"}},
	})

	// Valid session does not grant API access
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             urlIp + "/api/files/list",
		RequiredContent: []string{`{"Result":"error","ErrorMessage":"Unauthorized","ErrorCode":2}`},
		ExcludedContent: []string{"smallfile2"},
		ResultCode:      401,
		Cookies: []test.Cookie{{
			Name:  "session_token",
			Value: "validsession",
		}},
	})
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             urlIp + "/api/files/list",
		RequiredContent: []string{"smallfile2"},
		ExcludedContent: []string{"Unauthorized"},
		Headers:         []test.Header{{"apikey", "validkey"}},
	})
}

func TestDisableLogin(t *testing.T) {
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:         urlLocalhost + "/admin",
		RedirectUrl: "login",
		Cookies: []test.Cookie{{
			Name:  "session_token",
			Value: "invalid",
		}},
	})
	configuration.Get().Authentication.Method = models.AuthenticationDisabled
	authentication.Init(configuration.Get().Authentication)
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             urlLocalhost + "/admin",
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
		Url:    urlLocalhost + "/main.wasm",
		IsHtml: false,
	})
}
func TestServeWasmE2E(t *testing.T) {
	t.Parallel()
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:    urlLocalhost + "/e2e.wasm",
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
	resp, err := client.Get(urlIp + "/pubapi/file?id=pubapifileunprot1234")
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
	resp, err := client.Get(urlIp + "/pubapi/file?id=jpLXGJKigM4hjtA6T6sN")
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
	resp, err := client.Post(urlIp+"/pubapi/filepassword?id=jpLXGJKigM4hjtA6T6sN", "application/x-www-form-urlencoded", data)
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
	req, err := http.NewRequest("GET", urlIp+"/pubapi/file?id=jpLXGJKigM4hjtA6T6sN", nil)
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
	resp, err := client.Get(urlIp + "/pubapi/file?id=unknownfileid123456")
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
	resp, err := client.Post(urlIp+"/pubapi/filepassword?id=jpLXGJKigM4hjtA6T6sN", "application/x-www-form-urlencoded", data)
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
	resp, err := client.Post(urlIp+"/pubapi/filepassword?id=jpLXGJKigM4hjtA6T6sN", "application/x-www-form-urlencoded", data)
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
	req, err := http.NewRequest("POST", urlIp+"/pubapi/filepassword?id="+fileId, bytes.NewReader(payload))
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
// password the same way before verifying against the bundle's own hash.
func TestPublicApiFolderPasswordTrimMatchesSetTrim(t *testing.T) {
	t.Parallel()
	const rawPassword = "  FolderTrim12!  "
	trimmedHash := configuration.HashPassword(strings.TrimSpace(rawPassword), false, "")

	bundle := filebundle.Create("TestFolderTrimPw_"+helper.GenerateRandomString(8), 999)
	bundle.PasswordHash = trimmedHash
	database.SaveFileBundle(bundle)
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
	})

	client := &http.Client{}
	payload, err := json.Marshal(map[string]string{"password": rawPassword})
	if err != nil {
		t.Fatalf("Failed to marshal payload: %v", err)
	}
	req, err := http.NewRequest("POST", urlIp+"/pubapi/folderpassword?id="+bundle.Id, bytes.NewReader(payload))
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
	req, err := http.NewRequest(http.MethodGet, urlIp+"/pubapi/uploadrequest?id=testuploadreq123456", nil)
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

// TestEffectiveGuestMaxSizeMB is a pure, table-driven test for effectiveGuestMaxSizeMB - each of
// the three caps (server, guest, request) gets to be the binding minimum in turn, and an admin
// owner is confirmed to skip the guest cap entirely, matching isUserAllowedUnlimited's own
// "user.IsAdmin() -> true" short-circuit (Api.go).
func TestEffectiveGuestMaxSizeMB(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name          string
		serverMaxMB   int
		guestCapMB    int
		isOwnerAdmin  bool
		requestMaxMB  int
		expectedMaxMB int
	}{
		{"request cap is smallest", 1000, 500, false, 50, 50},
		{"server cap is smallest, request uncapped", 25, 10240, false, 0, 25},
		{"guest cap is smallest and binds", 1000, 10, false, 0, 10},
		{"guest cap would bind but is skipped for an admin owner", 1000, 10, true, 0, 1000},
		{"guest cap disabled (0) never binds", 1000, 0, false, 0, 1000},
		{"every cap uncapped except server", 1000, 0, false, 0, 1000},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := effectiveGuestMaxSizeMB(c.serverMaxMB, c.guestCapMB, c.isOwnerAdmin, c.requestMaxMB)
			if got != c.expectedMaxMB {
				t.Errorf("effectiveGuestMaxSizeMB(%d, %d, %v, %d) = %d, want %d",
					c.serverMaxMB, c.guestCapMB, c.isOwnerAdmin, c.requestMaxMB, got, c.expectedMaxMB)
			}
		})
	}
}

// TestPublicApiUploadRequestReportsEffectiveMaxSize is the failing-first test that GET
// /pubapi/uploadrequest reports the EFFECTIVE maxSizeMB (the server's own MaxFileSizeMB cap, here
// well below the request's own raw cap) rather than echoing request.MaxSize unchanged - the old
// behaviour that told a guest a limit the chunk path (apiChunkUploadRequestAdd) would silently
// override partway through the upload.
func TestPublicApiUploadRequestReportsEffectiveMaxSize(t *testing.T) {
	t.Parallel()

	testRequest := models.FileRequest{
		Id:       "testuploadreqmaxsize1",
		UserId:   5,
		MaxFiles: 10,
		// Deliberately far above the test server's own MaxFileSizeMB (25, see
		// testconfiguration.Create) so the server cap - not the request's raw value - must be
		// the one reported.
		MaxSize: 999999,
		Expiry:  time.Now().Add(24 * time.Hour).Unix(),
		Name:    "Test Upload Request Max Size",
		ApiKey:  "testkeymaxsize1",
	}
	database.SaveFileRequest(testRequest)

	client := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, urlIp+"/pubapi/uploadrequest?id=testuploadreqmaxsize1", nil)
	if err != nil {
		t.Fatalf("Failed to build request: %v", err)
	}
	req.Header.Set("apikey", "testkeymaxsize1")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}
	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	maxSizeMB, ok := response["maxSizeMB"].(float64)
	if !ok {
		t.Fatalf("Missing or invalid maxSizeMB field, got %v", response["maxSizeMB"])
	}
	expected := float64(configuration.Get().MaxFileSizeMB)
	if maxSizeMB != expected {
		t.Errorf("Expected effective maxSizeMB %v (the server cap, not the request's raw %d), got %v",
			expected, testRequest.MaxSize, maxSizeMB)
	}
}

// TestPublicApiUploadRequestReportsRemainingFilesAfterReservations is the failing-first test that
// GET /pubapi/uploadrequest reports remainingFiles via models.FileRequest.FilesRemaining(), which
// subtracts ReservedUploads (chunks a guest has started but not yet completed - see
// chunkreservation), rather than the old inline "MaxFiles - UploadedFiles" that ignored them and
// so overstated how much room was actually left, compared to what enforcement
// (checkFileRequestAndApiKey/FilesRemaining) would accept.
func TestPublicApiUploadRequestReportsRemainingFilesAfterReservations(t *testing.T) {
	t.Parallel()

	testRequest := models.FileRequest{
		Id:       "testuploadreqremain1",
		UserId:   5,
		MaxFiles: 5,
		MaxSize:  100,
		Expiry:   time.Now().Add(24 * time.Hour).Unix(),
		Name:     "Test Upload Request Remaining Files",
		ApiKey:   "testkeyremain1",
	}
	database.SaveFileRequest(testRequest)

	// UploadedFiles is not stored directly - Populate recomputes it from the files actually
	// associated with this request (see models.FileRequest.Populate), so two need to exist for
	// real.
	database.SaveMetaData(models.File{
		Id:              "remainfile1",
		Name:            "remainfile1",
		SHA1:            "03cfd743661f07975fa2f1220c5194cbaff48451",
		ExpireAt:        2147483646,
		UploadRequestId: testRequest.Id,
	})
	database.SaveMetaData(models.File{
		Id:              "remainfile2",
		Name:            "remainfile2",
		SHA1:            "03cfd743661f07975fa2f1220c5194cbaff48451",
		ExpireAt:        2147483646,
		UploadRequestId: testRequest.Id,
	})

	// One chunk reserved but not yet completed - MaxFiles(5) - UploadedFiles(2) - Reserved(1) = 2,
	// while the old "MaxFiles - UploadedFiles" formula would report 3.
	_, ok := chunkreservation.NewIfUnder(testRequest.Id, -1)
	if !ok {
		t.Fatalf("Failed to reserve a chunk for the test file request")
	}

	client := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, urlIp+"/pubapi/uploadrequest?id=testuploadreqremain1", nil)
	if err != nil {
		t.Fatalf("Failed to build request: %v", err)
	}
	req.Header.Set("apikey", "testkeyremain1")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}
	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	remainingFiles, ok := response["remainingFiles"].(float64)
	if !ok {
		t.Fatalf("Missing or invalid remainingFiles field, got %v", response["remainingFiles"])
	}
	if int(remainingFiles) != 2 {
		t.Errorf("Expected remainingFiles 2 (5 max - 2 uploaded - 1 reserved), got %v", remainingFiles)
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
	resp, err := client.Get(urlIp + "/pubapi/uploadrequest?id=testuploadreqquery12&key=testkey123")
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
	req, err := http.NewRequest(http.MethodGet, urlIp+"/pubapi/uploadrequest?id=expireduploadreq1234", nil)
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
	req, err := http.NewRequest(http.MethodGet, urlIp+"/pubapi/uploadrequest?id=closeduploadreq12345", nil)
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
	req, err := http.NewRequest(http.MethodGet, urlIp+"/pubapi/uploadrequest?id=testuploadreqkey1234", nil)
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

	resp, err := http.Get(urlIp + "/pubapi/uploadrequest?id=" + testRequest.Id)
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
	req, err := http.NewRequest(http.MethodGet, urlIp+"/pubapi/uploadrequest?id="+testRequest.Id, nil)
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

	resp, err := http.Get(urlIp + "/pubapi/uploadrequest?id=" + testRequest.Id + "&token=" + rawToken)
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
	req, err := http.NewRequest(http.MethodGet, urlIp+"/pubapi/uploadrequest?id="+testRequest.Id, nil)
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

	resp, err := http.Get(urlIp + "/pubapi/uploadrequest?id=" + testRequest.Id + "&token=" + rawToken)
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

	resp, err := http.Get(urlIp + "/pubapi/uploadrequest?id=" + testRequest.Id)
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
	firstResp, err := client.Get(urlIp + "/pubapi/uploadrequest?id=" + testRequest.Id + "&token=" + rawToken)
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

	req, err := http.NewRequest(http.MethodGet, urlIp+"/pubapi/uploadrequest?id="+testRequest.Id, nil)
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

	noCredResp, err := http.Get(urlIp + "/pubapi/uploadrequest?id=" + testRequest.Id)
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

	tokenResp, err := http.Get(urlIp + "/pubapi/uploadrequest?id=" + testRequest.Id + "&token=" + rawToken)
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
	resp, err := client.Get(urlIp + "/pubapi/folder?id=" + bundle.Id)
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
	resp, err := client.Get(urlIp + "/pubapi/folder?id=unknownfolder123456")
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

	folderResp, err := client.Get(urlIp + "/pubapi/folder?id=" + bundle.Id)
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

	zipResp, err := client.Get(urlIp + "/pubapi/folderzip?id=" + bundle.Id)
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
	req := httptest.NewRequest("GET", urlIp+"/", nil)
	shareaccess.WriteCookie(recorder, req, resourceType, resourceId, recipientId)
	cookies := recorder.Result().Cookies()
	return test.Cookie{Name: cookies[0].Name, Value: cookies[0].Value}
}

// TestFolderMemberCountAgreesWithRecipientMembership is a regression test for
// FileBundle.Populate and bundleMembers disagreeing about what belongs to a bundle:
// Populate used to exclude only IsPendingForDeletion, so a disposed member's bytes - no longer
// stored, see disposeFile - stayed counted in the owner's membercount and totalsizebytes, while
// bundleMembers (what a recipient is actually handed) already excluded disposed members. A
// folder with one expired member therefore showed the owner one more file, and more bytes, than
// a recipient could ever receive.
//
// Both callers now read models.File.IsBundleMember, so this drives them both from the exact same
// three-member input - one active, one disposed, one pending deletion - and checks the owner's
// count/size from Populate against the recipient's membership from bundleMembers directly. If
// either caller's exclusion rule is ever changed without touching IsBundleMember, or a future
// caller inlines its own check instead of using it, this starts disagreeing and fails.
func TestFolderMemberCountAgreesWithRecipientMembership(t *testing.T) {
	t.Parallel()
	bundle := models.FileBundle{Id: "bundle-consistency-" + helper.GenerateRandomString(8)}

	activeFile := models.File{
		Id:        "active-" + helper.GenerateRandomString(8),
		BundleId:  bundle.Id,
		SizeBytes: 111,
	}
	disposedFile := models.File{
		Id:         "disposed-" + helper.GenerateRandomString(8),
		BundleId:   bundle.Id,
		SizeBytes:  222,
		DisposedAt: time.Now().Unix(),
	}
	pendingFile := models.File{
		Id:              "pending-" + helper.GenerateRandomString(8),
		BundleId:        bundle.Id,
		SizeBytes:       333,
		PendingDeletion: time.Now().Unix(),
	}
	allFiles := map[string]models.File{
		activeFile.Id:   activeFile,
		disposedFile.Id: disposedFile,
		pendingFile.Id:  pendingFile,
	}

	_, ownerSize, ownerCount := bundle.Populate(allFiles)
	recipientMembers := bundleMembers(bundle.Id, allFiles)

	if ownerCount != 1 {
		t.Fatalf("owner count = %d, want 1 (only the active member, disposed and pending excluded)", ownerCount)
	}
	if ownerSize != activeFile.SizeBytes {
		t.Fatalf("owner total size = %d, want %d (only the active member's bytes)", ownerSize, activeFile.SizeBytes)
	}
	if len(recipientMembers) != ownerCount {
		t.Fatalf("recipient sees %d members but the owner's count says %d - the two disagree", len(recipientMembers), ownerCount)
	}
	var recipientSize int64
	for _, f := range recipientMembers {
		recipientSize += f.SizeBytes
	}
	if recipientSize != ownerSize {
		t.Fatalf("recipient total size = %d but owner total size = %d - the two disagree", recipientSize, ownerSize)
	}
}

// TestSingleFileCascadesRestrictedBundleDeniesAnonymous is a regression test for a
// broken-access-control bug: serveFile (/d, /dh, /downloadFile) and pubApiFileMetadata
// (/pubapi/file) checked only a file's own restriction, never whether the file is a member
// of a restricted bundle. A file with no grant of its own could therefore be pulled straight
// out of a restricted bundle by anyone holding the member's individual file id, bypassing the
// bundle's recipient ACL entirely.
//
// Since the folder-as-unit-of-sharing design, a member's own link is a fallback that redirects
// to the folder (see the early check at the top of serveFile/pubApiFileMetadata) rather than
// being resolved on its own, so both doors now defer authorisation entirely to the folder
// endpoints - this asserts an anonymous caller following that redirect is still denied, and that
// the member's name never appears anywhere in either response.
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

	client := &http.Client{}

	// /downloadFile redirects to /pubapi/folderzip, which the default client follows
	// automatically; the anonymous caller must still be denied there.
	resp, err := client.Get(urlIp + "/downloadFile?id=" + fileId)
	if err != nil {
		t.Fatalf("Failed to request download: %v", err)
	}
	downloadBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected the redirected request to be denied as not found, got status %d", resp.StatusCode)
	}
	if strings.Contains(string(downloadBody), secretFileName) {
		t.Errorf("Restricted member's name leaked through /downloadFile: %s", downloadBody)
	}

	// /pubapi/file redirects to /pubapi/folder, same reasoning.
	resp2, err := client.Get(urlIp + "/pubapi/file?id=" + fileId)
	if err != nil {
		t.Fatalf("Failed to request file metadata: %v", err)
	}
	defer resp2.Body.Close()
	metadataBody, _ := io.ReadAll(resp2.Body)
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("Expected the redirected metadata request to be denied as not found, got status %d", resp2.StatusCode)
	}
	if strings.Contains(string(metadataBody), secretFileName) {
		t.Errorf("Restricted member's name leaked through /pubapi/file: %s", metadataBody)
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
	resp, err := client.Get(urlIp + "/pubapi/file?id=" + fileId)
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

// TestPublicApiFileMetadataRateLimitsUnauthorisedIdentityRecipient is the failing-first test for
// closing the /pubapi/file timing oracle: an identity-restricted file answered a non-recipient
// with an immediate 200, while an unknown id went through respondPubApiNotFound and was throttled
// by ratelimiter.WaitOnFailedId - so a real, restricted id answered faster than a wrong guess,
// letting ids be enumerated by timing. pubApiFileMetadata must now consult the same limiter for a
// non-recipient, without changing the response itself: the "this link is for specific people"
// 200 is deliberately kept (see TestPublicApiFileMetadataHidesSizeExpiryForNonRecipient), only its
// timing changes.
//
// Rate limiting is switched on only for the duration of this test, against an id/IP pairing no
// other test in this file drives through pubApiFileMetadata, so as not to disturb - or be
// disturbed by - shared limiter state (see the identical concern in
// TestApiUnsealRateLimitReturns429). The handler is called directly rather than over the network
// listener so the RemoteAddr driving the limiter key is exact and not shared with any other test.
func TestPublicApiFileMetadataRateLimitsUnauthorisedIdentityRecipient(t *testing.T) {
	ratelimiter.SetUnitTestMode(false)
	t.Cleanup(func() { ratelimiter.SetUnitTestMode(true) })

	fileId := helper.GenerateRandomString(16)
	database.SaveMetaData(models.File{
		Id:                 fileId,
		Name:               "timing-oracle-restricted.txt",
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
		Email:     "timing-oracle-recipient@example.com",
		CreatedAt: time.Now().Unix(),
	})
	database.SetShareGrants(models.ShareResourceFile, fileId, []int{recipientId}, 999, 0)
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceFile, fileId)
		database.DeleteShareRecipient(recipientId)
		database.DeleteMetaData(fileId)
	})

	const ip = "203.0.113.201:54321"
	call := func() (int, map[string]interface{}) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/pubapi/file?id="+fileId, nil)
		r.RemoteAddr = ip
		pubApiFileMetadata(w, r)
		var body map[string]interface{}
		test.IsNil(t, json.NewDecoder(w.Body).Decode(&body))
		return w.Code, body
	}

	// WaitOnFailedId's burst of 10 lets the first ten calls through without blocking.
	var firstCode int
	var firstBody map[string]interface{}
	for i := 0; i < 10; i++ {
		firstCode, firstBody = call()
	}

	start := time.Now()
	lastCode, lastBody := call()
	elapsed := time.Since(start)

	if elapsed < 700*time.Millisecond {
		t.Fatalf("call past the burst returned in %v; expected WaitOnFailedId to have throttled it to ~1s, meaning the rate limiter was never consulted", elapsed)
	}

	// The response itself - status and body - must be exactly what a non-recipient always got;
	// only the timing above may differ from the pre-fix behaviour.
	test.IsEqualInt(t, firstCode, http.StatusOK)
	test.IsEqualInt(t, lastCode, http.StatusOK)
	test.IsEqual(t, lastBody, firstBody)
	test.IsEqual(t, lastBody["isAuthorised"], false)
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
		resp, err := http.Post(urlIp+"/pubapi/share/resend",
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

// TestPublicApiShareResendExpiredFileRequestMailsNothing guards against describeShareResource
// resolving a resource with a raw metadata lookup and no liveness check, which let
// /pubapi/share/resend keep mailing a valid-looking link for an
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
		resp, err := http.Post(urlIp+"/pubapi/share/resend",
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
		Url:             urlIp + "/downloadFile?id=" + fileId,
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
// unrestricted bundle, and a file that belongs to no bundle at all, must both still be
// reachable. The member's own link now redirects to its folder on every request, restricted or
// not (see the folder-as-unit-of-sharing design), so this follows that redirect (the default
// http.Client does so automatically) rather than expecting the member to be served directly; the
// no-bundle file is unaffected and served exactly as before.
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
		Url:             urlIp + "/downloadFile?id=" + memberFileId,
		RequiredContent: []string{"789"},
	})
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             urlIp + "/downloadFile?id=" + noBundleFileId,
		RequiredContent: []string{"456"},
	})

	client := &http.Client{}
	for _, id := range []string{memberFileId} {
		resp, err := client.Get(urlIp + "/pubapi/file?id=" + id)
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

// TestFolderZipExhaustedBundleAllowanceStillRefusesWhole asserts a zip request is refused once
// the recipient's own per-recipient bundle allowance (ShareGrants) is already exhausted, and -
// since member files no longer carry their own counter at all while bundled (see
// models.File.IsBundleMember and consumeBundleDownload) - that refusing the request touches
// nothing on the member rows themselves. A previous version of this test asserted the opposite:
// that the member-metering loop still spent each member's own DownloadCount before the (then
// last-checked) bundle allowance caught the exhaustion. That metering loop no longer exists; a
// refused zip request now leaves every member completely untouched.
func TestFolderZipExhaustedBundleAllowanceStillRefusesWhole(t *testing.T) {
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
	// A second recipient who never collects, so the folder itself is still alive while the first
	// is refused: each recipient has their own budget, and a folder is only over once the last of
	// them is finished with it (see storage.downloadAccessOf). Without them the folder would be
	// exhausted here and a concurrent CleanUp could collect the member rows this test inspects
	// afterwards.
	bystanderId := database.SaveShareRecipient(models.ShareRecipient{
		Email:     "zip-ordering-bystander@example.com",
		CreatedAt: time.Now().Unix(),
	})
	// Grant exactly one bundle download each, then immediately spend the first recipient's, so
	// their bundle allowance is already exhausted by the time the request under test arrives.
	database.SetShareGrants(models.ShareResourceBundle, bundle.Id, []int{recipientId, bystanderId}, 999, 1)
	if granted, _ := database.AcquireShareGrantDownload(models.ShareResourceBundle, bundle.Id, recipientId, time.Now().Unix(), 0); !granted {
		t.Fatalf("Failed to pre-exhaust the bundle allowance for the test fixture")
	}
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceBundle, bundle.Id)
		database.DeleteShareRecipient(recipientId)
		database.DeleteShareRecipient(bystanderId)
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
	req, err := http.NewRequest("GET", urlIp+"/pubapi/folderzip?id="+bundle.Id, nil)
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

	// No per-member metering loop exists any more: a refused request leaves every member's own
	// DownloadCount exactly as it was.
	for _, id := range []string{file1Id, file2Id} {
		file, ok := database.GetMetaDataById(id)
		if !ok {
			t.Fatalf("Fixture file %s vanished after the request", id)
		}
		if file.DownloadCount != countsBefore[id] {
			t.Errorf("Expected DownloadCount for %s to stay untouched by a refused request, got %d, want %d", id, file.DownloadCount, countsBefore[id])
		}
	}
}

// lastDownloadEntry returns the most recently written audit entry matching fileId and outcome,
// so a test can assert on the actor it was attributed to. Fails the test if none is found.
func lastDownloadEntry(t *testing.T, fileId string, outcome logging.AuditOutcome) logging.AuditEntry {
	t.Helper()
	entries, _ := logging.GetAuditEntriesSince(0, 2000)
	var found logging.AuditEntry
	ok := false
	for _, entry := range entries {
		if entry.Action != "download" || entry.FileId != fileId || entry.Outcome != outcome {
			continue
		}
		found = entry
		ok = true
	}
	if !ok {
		t.Fatalf("Expected a %q download audit entry for file %s, found none", outcome, fileId)
	}
	return found
}

// TestSingleFileRestrictedDownloadAttributesRecipient is a regression test for Part F: a
// recipient downloading a file directly restricted to them (not merely a bundle member) used to
// be recorded as anonymous, even though serveFile had already resolved their recipient id via
// recipientFor before calling storage.ServeFile. It must now be attributed to that recipient.
func TestSingleFileRestrictedDownloadAttributesRecipient(t *testing.T) {
	t.Parallel()
	fileId := helper.GenerateRandomString(16)
	database.SaveMetaData(models.File{
		Id:                 fileId,
		Name:               "restricted_single.txt",
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
		Email:     "single-file-recipient@example.com",
		CreatedAt: time.Now().Unix(),
	})
	database.SetShareGrants(models.ShareResourceFile, fileId, []int{recipientId}, 999, 0)
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceFile, fileId)
		database.DeleteShareRecipient(recipientId)
		database.DeleteMetaData(fileId)
	})

	cookie := testShareAccessCookie(models.ShareResourceFile, fileId, recipientId)
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             urlIp + "/downloadFile?id=" + fileId,
		RequiredContent: []string{"789"},
		Cookies:         []test.Cookie{cookie},
	})

	entry := lastDownloadEntry(t, fileId, logging.OutcomeSuccess)
	test.IsEqualBool(t, entry.Actor.Anonymous, false)
	test.IsEqualInt(t, entry.Actor.RecipientId, recipientId)
	test.IsEqualString(t, entry.Actor.RecipientEmail, "single-file-recipient@example.com")
}

// TestSingleFileUnrestrictedDownloadStaysAnonymous proves the recipient-attribution change in
// serveFile is additive: a file with no recipient list at all is downloaded exactly as before,
// with no user and no recipient attached to the request, and its audit entry stays anonymous.
func TestSingleFileUnrestrictedDownloadStaysAnonymous(t *testing.T) {
	t.Parallel()
	fileId := helper.GenerateRandomString(16)
	database.SaveMetaData(models.File{
		Id:                 fileId,
		Name:               "unrestricted_single.txt",
		Size:               "3 B",
		SizeBytes:          3,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ExpireAt:           2147483646,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		ContentType:        "text/plain",
		UserId:             999,
	})
	t.Cleanup(func() {
		database.DeleteMetaData(fileId)
	})

	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             urlIp + "/downloadFile?id=" + fileId,
		RequiredContent: []string{"789"},
	})

	entry := lastDownloadEntry(t, fileId, logging.OutcomeSuccess)
	test.IsEqualBool(t, entry.Actor.Anonymous, true)
	test.IsEqualInt(t, entry.Actor.RecipientId, 0)
	test.IsEqualString(t, entry.Actor.RecipientEmail, "")
}

// TestSingleFileRestrictedAllowanceExhaustedDenialAttributesRecipient proves the recipient is
// attached before both LogDownloadDenied calls in the restricted-file branch of serveFile, not
// only before the eventual successful LogDownload: a denial for an exhausted per-recipient
// allowance must also name who was denied, rather than falling back to anonymous.
//
// The share deliberately has a second recipient who never collects, so the file itself is still
// alive when the first is refused - each recipient has their own budget, and the file is only
// over once the last of them is finished. Without them this would be the different denial
// tested by TestSingleFileLastRecipientDenialAttributesRecipient: the file itself gone, refused
// at the door.
func TestSingleFileRestrictedAllowanceExhaustedDenialAttributesRecipient(t *testing.T) {
	t.Parallel()
	fileId := helper.GenerateRandomString(16)
	database.SaveMetaData(models.File{
		Id:                 fileId,
		Name:               "restricted_exhausted.txt",
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
		Email:     "exhausted-recipient@example.com",
		CreatedAt: time.Now().Unix(),
	})
	bystanderId := database.SaveShareRecipient(models.ShareRecipient{
		Email:     "exhausted-recipient-bystander@example.com",
		CreatedAt: time.Now().Unix(),
	})
	database.SetShareGrants(models.ShareResourceFile, fileId, []int{recipientId, bystanderId}, 999, 1)
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceFile, fileId)
		database.DeleteShareRecipient(recipientId)
		database.DeleteMetaData(fileId)
	})

	t.Cleanup(func() { database.DeleteShareRecipient(bystanderId) })

	cookie := testShareAccessCookie(models.ShareResourceFile, fileId, recipientId)

	// First download spends the one allowed download.
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             urlIp + "/downloadFile?id=" + fileId,
		RequiredContent: []string{"789"},
		Cookies:         []test.Cookie{cookie},
	})

	// The second is refused - allowance exhausted - and must still be attributed.
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequest("GET", urlIp+"/downloadFile?id="+fileId, nil)
	if err != nil {
		t.Fatalf("Failed to build request: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to request download: %v", err)
	}
	defer resp.Body.Close()

	entry := lastDownloadEntry(t, fileId, logging.OutcomeDenied)
	test.IsEqualBool(t, entry.Actor.Anonymous, false)
	test.IsEqualInt(t, entry.Actor.RecipientId, recipientId)
	test.IsEqualString(t, entry.Actor.RecipientEmail, "exhausted-recipient@example.com")
	test.IsEqualString(t, entry.Error, "recipient download allowance exhausted")
}

// TestFolderZipRestrictedAttributesEveryMemberToRecipient proves that ServeFilesAsZip's
// per-member LogDownload calls, driven from pubApiFolderZip, are all attributed to the
// recipient the bundle's restriction was resolved for - not just the top-level zip request.
func TestFolderZipRestrictedAttributesEveryMemberToRecipient(t *testing.T) {
	t.Parallel()
	uniqueName := "TestZipAttribution_" + helper.GenerateRandomString(8)
	bundle := filebundle.Create(uniqueName, 999)

	file1Id := helper.GenerateRandomString(16)
	database.SaveMetaData(models.File{
		Id:                 file1Id,
		Name:               "zip_attrib_one.txt",
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
		Name:               "zip_attrib_two.txt",
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
		Email:     "zip-attribution-recipient@example.com",
		CreatedAt: time.Now().Unix(),
	})
	database.SetShareGrants(models.ShareResourceBundle, bundle.Id, []int{recipientId}, 999, 0)
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceBundle, bundle.Id)
		database.DeleteShareRecipient(recipientId)
		database.DeleteMetaData(file1Id)
		database.DeleteMetaData(file2Id)
		filebundle.Delete(bundle)
	})

	cookie := testShareAccessCookie(models.ShareResourceBundle, bundle.Id, recipientId)
	client := &http.Client{}
	req, err := http.NewRequest("GET", urlIp+"/pubapi/folderzip?id="+bundle.Id, nil)
	if err != nil {
		t.Fatalf("Failed to build request: %v", err)
	}
	req.Header.Set("Cookie", cookie.Name+"="+cookie.Value)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to request folderzip: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected the zip request to succeed, got status %d", resp.StatusCode)
	}
	_, _ = io.Copy(io.Discard, resp.Body)

	for _, memberId := range []string{file1Id, file2Id} {
		entry := lastDownloadEntry(t, memberId, logging.OutcomeSuccess)
		test.IsEqualBool(t, entry.Actor.Anonymous, false)
		test.IsEqualInt(t, entry.Actor.RecipientId, recipientId)
		test.IsEqualString(t, entry.Actor.RecipientEmail, "zip-attribution-recipient@example.com")
	}
}

// TestShareLinkRedeemedLogsOnlyOnFirstOpen proves ShareGuard.recipientFor raises
// share.link.redeemed exactly once per recipient/resource pair: the first request presenting a
// valid access token logs the event, and a second request presenting the very same token again
// (recipientFor validates a presented token on every call, regardless of any cookie already
// held) does not log it a second time.
func TestShareLinkRedeemedLogsOnlyOnFirstOpen(t *testing.T) {
	t.Parallel()
	fileId := helper.GenerateRandomString(16)
	database.SaveMetaData(models.File{
		Id:                 fileId,
		Name:               "redeemed_once.txt",
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
		Email:     "redeemed-once@example.com",
		CreatedAt: time.Now().Unix(),
	})
	database.SetShareGrants(models.ShareResourceFile, fileId, []int{recipientId}, 999, 0)
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceFile, fileId)
		database.DeleteShareRecipient(recipientId)
		database.DeleteMetaData(fileId)
	})

	// A raw token, stored hashed the same way shareaccess.hashToken does it (SHA-256, hex),
	// bypassing the mail send so the test controls the raw value directly.
	rawToken := "raw-token-redeemed-" + helper.GenerateRandomString(8)
	sum := sha256.Sum256([]byte(rawToken))
	database.SaveShareLoginToken(models.ShareLoginToken{
		TokenHash:    hex.EncodeToString(sum[:]),
		RecipientId:  recipientId,
		ResourceType: models.ShareResourceFile,
		ResourceId:   fileId,
		CreatedAt:    time.Now().Unix(),
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
	})

	countRedeemed := func() int {
		entries, _ := logging.GetAuditEntriesSince(0, 2000)
		count := 0
		for _, entry := range entries {
			if entry.Action == "share.link.redeemed" && entry.FileId == fileId {
				count++
			}
		}
		return count
	}

	// First open: presents the token, is served, and logs the redemption once.
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             urlIp + "/downloadFile?id=" + fileId + "&token=" + rawToken,
		RequiredContent: []string{"789"},
	})
	time.Sleep(200 * time.Millisecond)
	test.IsEqualInt(t, countRedeemed(), 1)

	// Second open with the very same token: still served, but must not log a second redemption.
	test.HttpPageResult(t, test.HttpTestConfig{
		Url:             urlIp + "/downloadFile?id=" + fileId + "&token=" + rawToken,
		RequiredContent: []string{"789"},
	})
	time.Sleep(200 * time.Millisecond)
	test.IsEqualInt(t, countRedeemed(), 1)
}

// TestPublicApiConfig tests GET /pubapi/config for non-sensitive configuration values
func TestPublicApiConfig(t *testing.T) {
	t.Parallel()
	client := &http.Client{}
	resp, err := client.Get(urlIp + "/pubapi/config")
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

		// maxFilesGuestUpload/maxSizeGuestUploadMB must match GOKAPI_MAX_FILES_GUESTUPLOAD and
		// GOKAPI_MAX_SIZE_GUESTUPLOAD exactly - the same env values isUserAllowedUnlimited
		// (internal/webserver/api/Api.go) reads to cap a non-admin file request owner. Publishing
		// anything else would let RequestDialog show a max the server does not actually enforce.
		env := configuration.GetEnvironment()
		maxFilesGuestUpload, ok := limits["maxFilesGuestUpload"].(float64)
		if !ok {
			t.Errorf("Missing or invalid maxFilesGuestUpload field in limits")
		} else if int(maxFilesGuestUpload) != env.MaxFilesGuestUpload {
			t.Errorf("Expected maxFilesGuestUpload %d, got %v", env.MaxFilesGuestUpload, maxFilesGuestUpload)
		}
		maxSizeGuestUploadMB, ok := limits["maxSizeGuestUploadMB"].(float64)
		if !ok {
			t.Errorf("Missing or invalid maxSizeGuestUploadMB field in limits")
		} else if int(maxSizeGuestUploadMB) != env.MaxSizeGuestUploadMb {
			t.Errorf("Expected maxSizeGuestUploadMB %d, got %v", env.MaxSizeGuestUploadMb, maxSizeGuestUploadMB)
		}

		// downloadLeewaySeconds is the ONE surface GOKAPI_DOWNLOAD_LEEWAY has. It is published
		// here so the recipient's download page can state the policy, and deliberately nowhere
		// else - see TestDownloadLeewayIsNotOnAuthenticatedConfig for the other half.
		downloadLeewaySeconds, ok := limits["downloadLeewaySeconds"].(float64)
		if !ok {
			t.Errorf("Missing or invalid downloadLeewaySeconds field in limits")
		} else if int64(downloadLeewaySeconds) != int64(time.Duration(env.DownloadLeeway).Seconds()) {
			t.Errorf("Expected downloadLeewaySeconds %d, got %v", int64(time.Duration(env.DownloadLeeway).Seconds()), downloadLeewaySeconds)
		}
	}
}

// TestDownloadLeewayIsNotOnAuthenticatedConfig pins the other half of the leeway's one surface:
// it is server configuration, not a setting, so an authenticated caller - who could otherwise
// reasonably expect to be able to change what they can see - is never shown it. The public
// download page is told the policy; the uploader is not offered a control.
func TestDownloadLeewayIsNotOnAuthenticatedConfig(t *testing.T) {
	t.Parallel()
	for _, url := range []string{"http://127.0.0.1:53843/api/info/config", "http://127.0.0.1:53843/api/features"} {
		request, err := http.NewRequest("GET", url, nil)
		test.IsNil(t, err)
		request.Header.Set("apikey", "validkeyid7")
		response, err := http.DefaultClient.Do(request)
		test.IsNil(t, err)
		body, err := io.ReadAll(response.Body)
		test.IsNil(t, err)
		response.Body.Close()
		test.IsEqualInt(t, response.StatusCode, 200)
		test.IsEqualBool(t, strings.Contains(strings.ToLower(string(body)), "leeway"), false)
		test.IsEqualBool(t, strings.Contains(strings.ToLower(string(body)), "windowopenedat"), false)
	}
}

// TestPublicApiConfigNoSensitiveFields verifies that sensitive configuration is not exposed
func TestPublicApiConfigNoSensitiveFields(t *testing.T) {
	t.Parallel()
	client := &http.Client{}
	resp, err := client.Get(urlIp + "/pubapi/config")
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
	resp, err := client.Get(urlIp + "/pubapi/config")
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

// TestFolderPasswordGatesEveryMember is the replacement for the old
// TestFolderPasswordCrossMemberRejected, which asserted the pre-redesign "all protected members
// must match" bricking behaviour (see design doc section 3.1a) - that is exactly the bug this
// design fixes, so the old assertion is gone rather than adapted.
//
// The bundle now owns its own password (models.FileBundle.PasswordHash); members carry none of
// their own. This proves that gate is uniform: a wrong password is rejected and sets no cookie,
// the right one is accepted and sets a cookie, and - the part that matters - the SAME gate covers
// a request for a single named member through /pubapi/folderzip?ids=, not only the whole-folder
// endpoints. Two members are used, deliberately with no PasswordHash of their own, to prove the
// bundle's password is what gates them, not anything on the member rows.
func TestFolderPasswordGatesEveryMember(t *testing.T) {
	t.Parallel()
	uniqueName := "TestFolderPwGates_" + helper.GenerateRandomString(8)
	const rawPassword = "correct_folder_password"

	bundle := filebundle.Create(uniqueName, 999)
	bundle.PasswordHash = configuration.HashPassword(rawPassword, false, "")
	database.SaveFileBundle(bundle)

	member1Id := helper.GenerateRandomString(16)
	database.SaveMetaData(models.File{
		Id:                 member1Id,
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
	})
	member2Id := helper.GenerateRandomString(16)
	database.SaveMetaData(models.File{
		Id:                 member2Id,
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
	})
	t.Cleanup(func() {
		database.DeleteMetaData(member1Id)
		database.DeleteMetaData(member2Id)
		filebundle.Delete(bundle)
	})

	client := &http.Client{}

	// A single member requested directly through the zip door, with no cookie, is gated the
	// same as the whole folder: no bytes, just the requiresPassword prompt.
	zipResp, err := client.Get(urlIp + "/pubapi/folderzip?id=" + bundle.Id + "&ids=" + member1Id)
	if err != nil {
		t.Fatalf("Failed to request folderzip: %v", err)
	}
	zipBody, _ := io.ReadAll(zipResp.Body)
	zipResp.Body.Close()
	if zipResp.StatusCode != http.StatusOK {
		t.Errorf("Expected the password prompt (200), got status %d: %s", zipResp.StatusCode, zipBody)
	}
	if !strings.Contains(string(zipBody), `"requiresPassword":true`) {
		t.Errorf("Expected requiresPassword:true for a member request with no cookie, got %s", zipBody)
	}

	// A wrong password is rejected and sets no cookie.
	payloadWrongPw := []byte(`{"password":"not_the_password"}`)
	req, err := http.NewRequest("POST", urlIp+"/pubapi/folderpassword?id="+bundle.Id, bytes.NewReader(payloadWrongPw))
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
	if ok, exists := response["ok"].(bool); !exists || ok {
		t.Errorf("Expected ok=false, got %v", response["ok"])
	}
	for _, cookie := range resp.Cookies() {
		if strings.HasPrefix(cookie.Name, "b") {
			t.Errorf("Expected no bundle cookie to be set for a wrong password, but got %s", cookie.Name)
		}
	}

	// The right password is accepted and sets the bundle session cookie.
	payloadCorrectPw, err := json.Marshal(map[string]string{"password": rawPassword})
	if err != nil {
		t.Fatalf("Failed to marshal payload: %v", err)
	}
	req2, err := http.NewRequest("POST", urlIp+"/pubapi/folderpassword?id="+bundle.Id, bytes.NewReader(payloadCorrectPw))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("Failed to make POST request: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp2.StatusCode)
	}
	var response2 map[string]interface{}
	if err := json.NewDecoder(resp2.Body).Decode(&response2); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if ok, exists := response2["ok"].(bool); !exists || !ok {
		t.Errorf("Expected ok=true, got %v", response2["ok"])
	}
	var sessionCookie *http.Cookie
	for _, cookie := range resp2.Cookies() {
		if strings.HasPrefix(cookie.Name, "b") {
			sessionCookie = cookie
			break
		}
	}
	if sessionCookie == nil {
		t.Fatalf("Expected bundle cookie to be set")
	}

	// The same cookie now unlocks the OTHER member too - one password gates every member, not
	// just the one that happened to be requested when it was verified.
	req3, err := http.NewRequest("GET", urlIp+"/pubapi/folderzip?id="+bundle.Id+"&ids="+member2Id, nil)
	if err != nil {
		t.Fatalf("Failed to build request: %v", err)
	}
	req3.AddCookie(sessionCookie)
	resp3, err := client.Do(req3)
	if err != nil {
		t.Fatalf("Failed to request folderzip: %v", err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 for the second member once the folder is unlocked, got %d", resp3.StatusCode)
	}
	if contentType := resp3.Header.Get("Content-Type"); contentType != "text/plain" {
		t.Errorf("Expected the second member to be served raw, got Content-Type %s", contentType)
	}
}

// TestFolderLockedLeaksNothing tests that a password-protected folder without a valid cookie
// returns only id and requiresPassword fields, never name or files.
func TestFolderLockedLeaksNothing(t *testing.T) {
	t.Parallel()
	uniqueName := "TestFolderLocked_" + helper.GenerateRandomString(8)
	password := "secret_password"

	bundle := filebundle.Create(uniqueName, 999)
	bundle.PasswordHash = configuration.HashPassword(password, false, "")
	database.SaveFileBundle(bundle)

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
	})

	client := &http.Client{}
	resp, err := client.Get(urlIp + "/pubapi/folder?id=" + bundle.Id)
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

// TestPublicApiFolderDeadMembersLeaksNothing guards against pubApiFolder returning 200 with
// `"name": bundle.Name` even when the folder has expired. Since the folder-as-unit-of-sharing
// design, expiry lives on the bundle itself (models.FileBundle.ExpireAt) rather than being
// inferred from members - a member's own ExpireAt is inert while it belongs to a bundle - so
// this now expires the BUNDLE, with a live, otherwise-unremarkable member underneath it. This
// asserts a dead folder's name never appears anywhere in the response, and that a
// protected-but-dead folder does not report requiresPassword: false.
func TestPublicApiFolderDeadMembersLeaksNothing(t *testing.T) {
	t.Parallel()

	// Case 1: an unprotected folder that has itself already expired.
	uniqueName := "TestFolderDead_" + helper.GenerateRandomString(8)
	bundle := filebundle.Create(uniqueName, 999)
	bundle.ExpireAt = time.Now().Add(-1 * time.Hour).Unix()
	bundle.UnlimitedTime = false
	database.SaveFileBundle(bundle)
	database.SaveMetaData(models.File{
		Id:                 helper.GenerateRandomString(16),
		Name:               "dead_unprotected.txt",
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
	resp, err := client.Get(urlIp + "/pubapi/folder?id=" + bundle.Id)
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

	// Case 2: a folder that is BOTH password protected AND already expired - the case that used
	// to skip the password gate entirely and hand back the name unlocked.
	protectedName := "TestFolderDeadProtected_" + helper.GenerateRandomString(8)
	protectedBundle := filebundle.Create(protectedName, 999)
	protectedBundle.PasswordHash = configuration.HashPassword("dead_secret_password", false, "")
	protectedBundle.ExpireAt = time.Now().Add(-1 * time.Hour).Unix()
	protectedBundle.UnlimitedTime = false
	database.SaveFileBundle(protectedBundle)
	database.SaveMetaData(models.File{
		Id:                 helper.GenerateRandomString(16),
		Name:               "dead_protected.txt",
		Size:               "10 B",
		SizeBytes:          10,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ExpireAt:           2147483646,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		ContentType:        "text/plain",
		UserId:             999,
		BundleId:           protectedBundle.Id,
	})

	resp2, err := client.Get(urlIp + "/pubapi/folder?id=" + protectedBundle.Id)
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

// TestFolderZipCounterEnforced proves the folder's own DownloadsRemaining
// (models.FileBundle.DownloadsRemaining) is the single counter that gates both a zip download
// and a single-member download, replacing the old per-member counters entirely: a two-member
// bundle with an allowance of 1 serves the zip once, then refuses both a second zip request AND
// a single-member request - the same allowance, exhausted by whichever came first.
func TestFolderZipCounterEnforced(t *testing.T) {
	t.Parallel()
	uniqueName := "TestFolderCounter_" + helper.GenerateRandomString(8)

	bundle := filebundle.Create(uniqueName, 999)
	bundle.UnlimitedDownloads = false
	bundle.DownloadsRemaining = 1
	database.SaveFileBundle(bundle)

	member1Id := helper.GenerateRandomString(16)
	database.SaveMetaData(models.File{
		Id:                 member1Id,
		Name:               "one.txt",
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
	member2Id := helper.GenerateRandomString(16)
	database.SaveMetaData(models.File{
		Id:                 member2Id,
		Name:               "two.txt",
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
	t.Cleanup(func() {
		database.DeleteMetaData(member1Id)
		database.DeleteMetaData(member2Id)
		filebundle.Delete(bundle)
	})

	client := &http.Client{}

	// First request: the whole zip (no ids=, so len(requestedMembers) == 2), spends the folder's
	// one and only download.
	firstReq, err := http.NewRequest("GET", urlIp+"/pubapi/folderzip?id="+bundle.Id, nil)
	if err != nil {
		t.Fatalf("Failed to create first request: %v", err)
	}
	resp1, err := client.Do(firstReq)
	if err != nil {
		t.Fatalf("Failed to make first request: %v", err)
	}
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 for the first (zip) download, got %d", resp1.StatusCode)
	}
	if contentType := resp1.Header.Get("Content-Type"); contentType != "application/zip" {
		t.Errorf("Expected a zip response for a two-member bundle, got Content-Type %s", contentType)
	}
	stored, ok := database.GetFileBundle(bundle.Id)
	if !ok {
		t.Fatalf("Bundle vanished after the first request")
	}
	if stored.DownloadsRemaining != 0 {
		t.Errorf("Expected the zip download to consume the folder's one allowance, got %d remaining", stored.DownloadsRemaining)
	}

	// Second request: the folder's allowance is exhausted. A second whole-zip request must be
	// refused as a whole - no partial archive.
	secondReq, err := http.NewRequest("GET", urlIp+"/pubapi/folderzip?id="+bundle.Id, nil)
	if err != nil {
		t.Fatalf("Failed to create second request: %v", err)
	}
	resp2, err := client.Do(secondReq)
	if err != nil {
		t.Fatalf("Failed to make second request: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404 refusing the whole request once the folder's allowance is exhausted, got %d", resp2.StatusCode)
	}
	if contentType := resp2.Header.Get("Content-Type"); contentType == "application/zip" {
		t.Errorf("Expected no archive body once the allowance is exhausted, got a zip response: %s", body2)
	}

	// Third request: a SINGLE member, drawing from the same now-exhausted allowance, must also
	// be refused - proving the zip and single-member doors share one counter, not two.
	thirdReq, err := http.NewRequest("GET", urlIp+"/pubapi/folderzip?id="+bundle.Id+"&ids="+member1Id, nil)
	if err != nil {
		t.Fatalf("Failed to create third request: %v", err)
	}
	resp3, err := client.Do(thirdReq)
	if err != nil {
		t.Fatalf("Failed to make third request: %v", err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404 for a single-member request against the same exhausted allowance, got %d", resp3.StatusCode)
	}

	stored, ok = database.GetFileBundle(bundle.Id)
	if !ok {
		t.Fatalf("Bundle vanished after the refused requests")
	}
	if stored.DownloadsRemaining != 0 {
		t.Errorf("Exhausted allowance must not go negative or be re-consumed by refused requests, got %d remaining", stored.DownloadsRemaining)
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

// TestFolderZipMemberOwnDownloadFieldsAreInert proves the core data-model change of the
// folder-as-unit-of-sharing design: a member's own DownloadsRemaining/UnlimitedDownloads no
// longer decide anything once it belongs to a bundle. Two of three members carry
// DownloadsRemaining: 0 - which, under the old per-member-counter design, would have made
// pubApiFolderZip's old servable-member scan silently narrow the archive down to the one
// surviving member (or refuse the whole request, depending on which fix was live at the time).
// With the bundle itself left unlimited, the whole zip must now succeed and contain all three.
func TestFolderZipMemberOwnDownloadFieldsAreInert(t *testing.T) {
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
	resp, err := client.Get(urlIp + "/pubapi/folderzip?id=" + bundle.Id)
	if err != nil {
		t.Fatalf("Failed to request folderzip: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected the whole request to succeed - the bundle itself is unlimited, so its members' own DownloadsRemaining must not matter - got status %d: %s", resp.StatusCode, body)
	}
	if contentType := resp.Header.Get("Content-Type"); contentType != "application/zip" {
		t.Errorf("Expected all three members to be served as one archive, got Content-Type %s", contentType)
	}
}

// TestFolderZipConcurrentVisitsExactlyOneSucceeds replaces the old hook-driven
// TestFolderZipRaceWindowRefusesWhole/TestFolderZipRaceWindowLeavesBundleAllowanceUntouched pair.
// Those simulated a race between per-member counter decrements in pubApiFolderZip's old metering
// loop - a loop that no longer exists, since a member's own DownloadsRemaining is inert while it
// belongs to a bundle (see models.File.IsBundleMember). The only shared mutable state left to
// race is the bundle's own DownloadsRemaining, spent exactly once per request by
// consumeBundleDownload - and that decrement is a single atomic, conditional database statement
// (see DecreaseBundleDownloadsRemaining in each provider), so this drives real concurrent
// requests at it rather than simulating an interleaving by hand: with the allowance set to 1,
// exactly one of several simultaneous zip requests must succeed and the rest must be refused.
func TestFolderZipConcurrentVisitsExactlyOneSucceeds(t *testing.T) {
	t.Parallel()
	uniqueName := "TestFolderConcurrentVisits_" + helper.GenerateRandomString(8)
	bundle := filebundle.Create(uniqueName, 999)
	bundle.UnlimitedDownloads = false
	bundle.DownloadsRemaining = 1
	database.SaveFileBundle(bundle)

	memberId := helper.GenerateRandomString(16)
	database.SaveMetaData(models.File{
		Id:                 memberId,
		Name:               "concurrent.txt",
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
	t.Cleanup(func() {
		database.DeleteMetaData(memberId)
		filebundle.Delete(bundle)
	})

	const attempts = 10
	statusCodes := make([]int, attempts)
	var wg sync.WaitGroup
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func(i int) {
			defer wg.Done()
			client := &http.Client{}
			resp, err := client.Get(urlIp + "/pubapi/folderzip?id=" + bundle.Id)
			if err != nil {
				t.Errorf("Failed to request folderzip: %v", err)
				return
			}
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)
			statusCodes[i] = resp.StatusCode
		}(i)
	}
	wg.Wait()

	succeeded := 0
	for _, code := range statusCodes {
		switch code {
		case http.StatusOK:
			succeeded++
		case http.StatusNotFound:
			// expected for every attempt but the one that wins the allowance
		default:
			t.Errorf("Unexpected status code %d among concurrent requests", code)
		}
	}
	if succeeded != 1 {
		t.Errorf("Expected exactly 1 of %d concurrent requests to succeed against a folder with one download remaining, got %d", attempts, succeeded)
	}

	stored, ok := database.GetFileBundle(bundle.Id)
	if !ok {
		t.Fatalf("Bundle vanished after the concurrent requests")
	}
	if stored.DownloadsRemaining != 0 {
		t.Errorf("Expected the folder's allowance to end at 0, got %d", stored.DownloadsRemaining)
	}
}

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

	resp1, err := client.Get(urlIp + "/pubapi/folderzip?id=" + bundle1.Id + "&ids=" + file1Id + "," + file2Id)
	if err != nil {
		t.Errorf("Failed to make request with cross-bundle ids: %v", err)
		return
	}
	resp1.Body.Close()

	if resp1.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400 for cross-bundle ids, got %d", resp1.StatusCode)
	}

	resp2, err := client.Get(urlIp + "/pubapi/folder?id=" + bundle1.Id)
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

	resp3, err := client.Get(urlIp + "/pubapi/folderzip?id=" + bundle1.Id)
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
