//go:build !integration && test

package webserver

import (
	"bufio"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/storage/processingstatus"
	"github.com/forceu/gokapi/internal/test"
	"github.com/forceu/gokapi/internal/test/testconfiguration"
	"github.com/forceu/gokapi/internal/webserver/authentication"
	"github.com/forceu/gokapi/internal/webserver/authentication/csrftoken"
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
	if name, ok := response["name"]; !ok || name != "" {
		t.Errorf("Expected name to be empty for password-protected file, got %v", name)
	}
	if requiresPw, ok := response["requiresPassword"]; !ok || requiresPw != true {
		t.Errorf("Expected requiresPassword true, got %v", requiresPw)
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
