package logging

import (
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/test"
	"github.com/forceu/gokapi/internal/test/testconfiguration"
)

func TestMain(m *testing.M) {
	testconfiguration.Create(false)
	exitVal := m.Run()
	testconfiguration.Delete()
	os.Exit(exitVal)
}

func TestGetIpAddress(t *testing.T) {
	Init("test")
	r := httptest.NewRequest("GET", "/test", nil)
	test.IsEqualString(t, GetIpAddress(r), "192.0.2.1")
	r = httptest.NewRequest("GET", "/test", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	test.IsEqualString(t, GetIpAddress(r), "127.0.0.1")
	r.RemoteAddr = "invalid"
	test.IsEqualString(t, GetIpAddress(r), "invalid")
	r.Header.Add("X-REAL-IP", "invalid")
	test.IsEqualString(t, GetIpAddress(r), "invalid")
	r.Header.Add("X-FORWARDED-FOR", "invalid")
	test.IsEqualString(t, GetIpAddress(r), "invalid")
	r.RemoteAddr = "127.0.0.1"
	r.Header.Del("X-REAL-IP")
	r.Header.Del("X-FORWARDED-FOR")
	test.IsEqualString(t, GetIpAddress(r), "127.0.0.1")
	r.Header.Add("X-REAL-IP", "1.1.1.1")
	test.IsEqualString(t, GetIpAddress(r), "1.1.1.1")
	r.Header.Add("X-FORWARDED-FOR", "1.1.1.1, 2.2.2.2")
	test.IsEqualString(t, GetIpAddress(r), "2.2.2.2")
	useCloudflare = true
	r.Header.Add("CF-Connecting-IP", "3.3.3.3")
	test.IsEqualString(t, GetIpAddress(r), "3.3.3.3")
}

func TestInit(t *testing.T) {
	Init("test")
	test.IsEqualString(t, logPath, "test/log.txt")
}

func TestAddString(t *testing.T) {
	test.FileDoesNotExist(t, "test/log.txt")
	createLogEntry(categoryInfo, "Hello", true)
	test.FileExists(t, "test/log.txt")
	content, _ := os.ReadFile("test/log.txt")
	test.IsEqualBool(t, strings.Contains(string(content), "UTC   [info] Hello"), true)
}

func TestAddDownload(t *testing.T) {
	file := models.File{
		Id:   "testId",
		Name: "testName",
	}
	r := httptest.NewRequest("GET", "/test", nil)
	r.RemoteAddr = "127.0.0.1"
	r.Header.Set("User-Agent", "testAgent")
	r.Header.Add("X-REAL-IP", "1.1.1.1")
	err := LogDownload(file, r, true)
	test.IsNil(t, err)
	// Need sleep, as the human-readable log.txt write is non-blocking (the audit chain write
	// itself is synchronous and already completed by the time LogDownload() returned above)
	time.Sleep(500 * time.Millisecond)
	content, _ := os.ReadFile("test/log.txt")
	test.IsEqualBool(t, strings.Contains(string(content), "UTC   [download] IP 1.1.1.1, ID testId, Useragent testAgent"), true)
	r.Header.Add("X-REAL-IP", "2.2.2.2")
	err = LogDownload(file, r, false)
	test.IsNil(t, err)
	// Need sleep, as LogDownload() is non-blocking
	time.Sleep(500 * time.Millisecond)
	content, _ = os.ReadFile("test/log.txt")
	test.IsEqualBool(t, strings.Contains(string(content), "2.2.2.2"), false)
}

// TestLogUserCreationIncludesAuthProvider verifies MINOR-3: the audit detail for user.created
// must include AuthProvider, so that provisioning a user for OAuth/OIDC (e.g. authprovider:
// google via user/create) is distinguishable in the audit log from an ordinary internal-auth user
// creation. Before this fix, the detail only carried the target user's name and id, so an
// attacker@gmail.com provisioned with authprovider google looked identical in the log to any
// other new user.
func TestLogUserCreationIncludesAuthProvider(t *testing.T) {
	dir := t.TempDir()
	Init(dir)

	googleUser := models.User{Id: 42, Name: "attacker@gmail.com", AuthProvider: models.AuthProviderGoogle}
	editor := models.User{Id: 1, Name: "admin"}
	LogUserCreation(googleUser, editor)

	// appendAuditEntryAsync writes on a goroutine; give it time to land.
	time.Sleep(500 * time.Millisecond)

	entries, _ := GetAuditEntriesSince(0, 100)
	found := false
	for _, entry := range entries {
		if entry.Action != "user.created" {
			continue
		}
		found = true
		test.IsEqualBool(t, strings.Contains(entry.Detail, "attacker@gmail.com"), true)
		test.IsEqualBool(t, strings.Contains(entry.Detail, models.AuthProviderGoogle), true)
	}
	test.IsEqualBool(t, found, true)
}

func TestLogDownloadDenied(t *testing.T) {
	Init("test")
	file := models.File{Id: "deniedTestId", Name: "deniedTestName"}
	r := httptest.NewRequest("GET", "/test", nil)
	r.RemoteAddr = "127.0.0.1" // default trusted proxy, so the X-REAL-IP header below is honoured
	r.Header.Add("X-REAL-IP", "9.9.9.9")
	err := LogDownloadDenied(file, r, true, "incorrect password")
	test.IsNil(t, err)
	time.Sleep(500 * time.Millisecond)
	content, _ := os.ReadFile("test/log.txt")
	test.IsEqualBool(t, strings.Contains(string(content), "[denied] ID deniedTestId, IP 9.9.9.9, download denied: incorrect password"), true)
}

// TestLogDownloadFailClosed verifies the W7 fail-closed contract at the logging package level:
// if the durable local audit write fails, LogDownload (and LogDownloadDenied, which is on the
// same guarded path) must report it via a non-nil error rather than silently succeeding, so
// that a caller serving file content knows to refuse the request instead.
func TestLogDownloadFailClosed(t *testing.T) {
	dir := t.TempDir()
	Init(dir)
	// os.OpenFile() on a directory fails regardless of user/permissions, giving a reliable way
	// to force the audit write to fail without depending on filesystem permission behaviour.
	test.IsNil(t, os.RemoveAll(auditLogPath))
	test.IsNil(t, os.MkdirAll(auditLogPath, 0777))

	file := models.File{Id: "failClosedTestId", Name: "failClosedTestName"}
	r := httptest.NewRequest("GET", "/test", nil)

	err := LogDownload(file, r, false)
	test.IsNotNil(t, err)

	err = LogDownloadDenied(file, r, false, "link expired")
	test.IsNotNil(t, err)

	err = LogUpload(file, models.User{Id: 1, Name: "someuser"}, models.FileRequest{}, r, false)
	test.IsNotNil(t, err)

	// LogDelete and LogFolderDeleteBatch used to be fire-and-forget (appendAuditEntryAsync), so a
	// local write failure here was invisible to the caller and a folder/file was deleted with
	// no durable audit record of it. They are now fail-closed like the rest of this test.
	err = LogDelete(file, models.User{Id: 1, Name: "someuser"})
	test.IsNotNil(t, err)

	err = LogFolderDeleteBatch(models.FileBundle{Id: "failClosedBundleId", Name: "failClosedBundleName"},
		[]models.File{{Id: "failClosedMemberId", Name: "failClosedMemberName"}}, models.User{Id: 1, Name: "someuser"})
	test.IsNotNil(t, err)

	// Give the fire-and-forget human-readable log.txt writes (spawned regardless of the audit
	// outcome) time to land before the temp dir is removed.
	time.Sleep(300 * time.Millisecond)
}
