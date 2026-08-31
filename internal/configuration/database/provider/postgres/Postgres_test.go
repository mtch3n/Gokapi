//go:build test

package postgres

import (
	neturl "net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/test"
)

// testDbUrlEnv holds a DSN to a disposable PostgreSQL database, for example
// postgres://gokapi:testpw@127.0.0.1:15432/gokapi_test?sslmode=disable
// If unset, every test in this file is skipped, so the suite still runs on
// machines without a PostgreSQL server.
const testDbUrlEnv = "GOKAPI_TEST_POSTGRES_URL"

var dbInstance DatabaseProvider

func testConfig(t *testing.T) models.DbConnection {
	t.Helper()
	url := os.Getenv(testDbUrlEnv)
	if url == "" {
		t.Skipf("%s not set, skipping PostgreSQL provider tests", testDbUrlEnv)
	}
	return connectionFromDsn(t, url)
}

// connectionFromDsn splits the DSN in GOKAPI_TEST_POSTGRES_URL into the individual
// connection fields, the same way database.ParseUrl does for the real configuration.
func connectionFromDsn(t *testing.T, dsn string) models.DbConnection {
	t.Helper()
	parsed, err := neturl.Parse(dsn)
	test.IsNil(t, err)
	password, _ := parsed.User.Password()
	return models.DbConnection{
		HostUrl:         parsed.Host,
		DatabaseName:    strings.TrimPrefix(parsed.Path, "/"),
		Username:        parsed.User.Username(),
		Password:        password,
		PostgresSslMode: parsed.Query().Get("sslmode"),
		Type:            2, // dbabstraction.TypePostgres
	}
}

// dropAllTables gives each run a clean schema, so tests never inherit state.
func dropAllTables(t *testing.T, p DatabaseProvider) {
	t.Helper()
	err := p.rawPostgres(`DROP TABLE IF EXISTS ApiKeys, E2EConfig, FileMetaData, Hotlinks,
		Sessions, Users, UploadRequests, Statistics, SchemaVersion CASCADE;`)
	test.IsNil(t, err)
}

func TestMain(m *testing.M) {
	url := os.Getenv(testDbUrlEnv)
	if url == "" {
		os.Exit(m.Run())
	}
	parsed, errParse := neturl.Parse(url)
	if errParse != nil {
		os.Exit(1)
	}
	password, _ := parsed.User.Password()
	instance, err := New(models.DbConnection{
		HostUrl:         parsed.Host,
		DatabaseName:    strings.TrimPrefix(parsed.Path, "/"),
		Username:        parsed.User.Username(),
		Password:        password,
		PostgresSslMode: parsed.Query().Get("sslmode"),
		Type:            2,
	})
	if err == nil {
		_ = instance.rawPostgres(`DROP TABLE IF EXISTS ApiKeys, E2EConfig, FileMetaData, Hotlinks,
			Sessions, Users, UploadRequests, Statistics, SchemaVersion CASCADE;`)
		instance.Close()
	}
	os.Exit(m.Run())
}

func TestInit(t *testing.T) {
	config := testConfig(t)
	instance, err := New(config)
	test.IsNil(t, err)
	dbInstance = instance
	test.IsEqualInt(t, dbInstance.GetType(), 2)
	test.IsEqualInt(t, dbInstance.GetSchemaVersion(), DatabaseSchemeVersion)
	test.IsEqualInt(t, dbInstance.GetDbVersion(), DatabaseSchemeVersion)
}

func TestInitRejectsEmptyUrl(t *testing.T) {
	_, err := New(models.DbConnection{HostUrl: ""})
	test.IsNotNil(t, err)
}

func TestSetDbVersion(t *testing.T) {
	testConfig(t)
	dbInstance.SetDbVersion(12)
	test.IsEqualInt(t, dbInstance.GetDbVersion(), 12)
	dbInstance.SetDbVersion(DatabaseSchemeVersion)
	test.IsEqualInt(t, dbInstance.GetDbVersion(), DatabaseSchemeVersion)
}

func TestApiKeys(t *testing.T) {
	testConfig(t)
	key := models.ApiKey{
		Id:              "apikey-1",
		PublicId:        "public-1",
		FriendlyName:    "Test Key",
		LastUsed:        100,
		Permissions:     models.ApiPermDefault,
		Expiry:          0,
		IsSystemKey:     false,
		UserId:          5,
		UploadRequestId: "req-1",
	}
	dbInstance.SaveApiKey(key)

	retrieved, ok := dbInstance.GetApiKey("apikey-1")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, retrieved.FriendlyName, "Test Key")
	test.IsEqualString(t, retrieved.PublicId, "public-1")
	test.IsEqualInt(t, retrieved.UserId, 5)
	test.IsEqualString(t, retrieved.UploadRequestId, "req-1")
	test.IsEqualBool(t, retrieved.IsSystemKey, false)

	// Upsert must overwrite rather than duplicate
	key.FriendlyName = "Renamed"
	dbInstance.SaveApiKey(key)
	retrieved, ok = dbInstance.GetApiKey("apikey-1")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, retrieved.FriendlyName, "Renamed")

	id, ok := dbInstance.GetApiKeyByPublicKey("public-1")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, id, "apikey-1")

	_, ok = dbInstance.GetApiKeyByPublicKey("does-not-exist")
	test.IsEqualBool(t, ok, false)

	key.LastUsed = 500
	dbInstance.UpdateTimeApiKey(key)
	retrieved, _ = dbInstance.GetApiKey("apikey-1")
	test.IsEqualInt(t, int(retrieved.LastUsed), 500)

	all := dbInstance.GetAllApiKeys()
	test.IsEqualInt(t, len(all), 1)

	dbInstance.DeleteApiKey("apikey-1")
	_, ok = dbInstance.GetApiKey("apikey-1")
	test.IsEqualBool(t, ok, false)
}

func TestApiKeyExpiry(t *testing.T) {
	testConfig(t)
	currentTime = func() time.Time { return time.Unix(1000, 0) }
	defer func() { currentTime = time.Now }()

	dbInstance.SaveApiKey(models.ApiKey{Id: "expired", PublicId: "pub-expired", Expiry: 500})
	dbInstance.SaveApiKey(models.ApiKey{Id: "valid", PublicId: "pub-valid", Expiry: 5000})
	dbInstance.SaveApiKey(models.ApiKey{Id: "noexpiry", PublicId: "pub-noexpiry", Expiry: 0})

	all := dbInstance.GetAllApiKeys()
	_, hasExpired := all["expired"]
	test.IsEqualBool(t, hasExpired, false)
	_, hasValid := all["valid"]
	test.IsEqualBool(t, hasValid, true)
	_, hasNoExpiry := all["noexpiry"]
	test.IsEqualBool(t, hasNoExpiry, true)

	// Garbage collection must remove only the expired key
	dbInstance.RunGarbageCollection()
	_, ok := dbInstance.GetApiKey("expired")
	test.IsEqualBool(t, ok, false)
	_, ok = dbInstance.GetApiKey("valid")
	test.IsEqualBool(t, ok, true)

	dbInstance.DeleteApiKey("valid")
	dbInstance.DeleteApiKey("noexpiry")
}

func TestFileMetaData(t *testing.T) {
	testConfig(t)
	file := models.File{
		Id:                 "file-1",
		Name:               "secret.pdf",
		Size:               "1 MB",
		SHA1:               "abc123",
		ExpireAt:           9999,
		SizeBytes:          1048576,
		DownloadsRemaining: 3,
		DownloadCount:      0,
		PasswordHash:       "hash",
		HotlinkId:          "",
		ContentType:        "application/pdf",
		AwsBucket:          "bucket",
		Encryption:         models.EncryptionInfo{IsEncrypted: true, IsEndToEndEncrypted: true},
		UnlimitedDownloads: false,
		UnlimitedTime:      false,
		UserId:             7,
		UploadDate:         1234,
		PendingDeletion:    0,
		UploadRequestId:    "req-1",
	}
	dbInstance.SaveMetaData(file)

	retrieved, ok := dbInstance.GetMetaDataById("file-1")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, retrieved.Name, "secret.pdf")
	test.IsEqualString(t, retrieved.SHA1, "abc123")
	test.IsEqualInt(t, retrieved.UserId, 7)
	test.IsEqualInt(t, retrieved.DownloadsRemaining, 3)
	// The gob-encoded BYTEA column must survive the round trip
	test.IsEqualBool(t, retrieved.Encryption.IsEncrypted, true)
	test.IsEqualBool(t, retrieved.Encryption.IsEndToEndEncrypted, true)
	test.IsEqualBool(t, retrieved.UnlimitedDownloads, false)

	test.IsEqualInt(t, dbInstance.GetDownloadsRemaining("file-1"), 3)

	dbInstance.IncreaseDownloadCount("file-1", true)
	retrieved, _ = dbInstance.GetMetaDataById("file-1")
	test.IsEqualInt(t, retrieved.DownloadCount, 1)
	test.IsEqualInt(t, retrieved.DownloadsRemaining, 2)

	dbInstance.IncreaseDownloadCount("file-1", false)
	retrieved, _ = dbInstance.GetMetaDataById("file-1")
	test.IsEqualInt(t, retrieved.DownloadCount, 2)
	test.IsEqualInt(t, retrieved.DownloadsRemaining, 2)

	all := dbInstance.GetAllMetadata()
	test.IsEqualInt(t, len(all), 1)

	dbInstance.DeleteMetaData("file-1")
	_, ok = dbInstance.GetMetaDataById("file-1")
	test.IsEqualBool(t, ok, false)
}

func TestHotlinks(t *testing.T) {
	testConfig(t)
	dbInstance.SaveHotlink(models.File{Id: "file-h", HotlinkId: "hot-1"})

	fileId, ok := dbInstance.GetHotlink("hot-1")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, fileId, "file-h")

	_, ok = dbInstance.GetHotlink("nonexistent")
	test.IsEqualBool(t, ok, false)

	all := dbInstance.GetAllHotlinks()
	test.IsEqualInt(t, len(all), 1)
	test.IsEqualString(t, all[0], "hot-1")

	// Empty id must be a no-op rather than deleting everything
	dbInstance.DeleteHotlink("")
	test.IsEqualInt(t, len(dbInstance.GetAllHotlinks()), 1)

	dbInstance.DeleteHotlink("hot-1")
	test.IsEqualInt(t, len(dbInstance.GetAllHotlinks()), 0)
}

func TestSessions(t *testing.T) {
	testConfig(t)
	session := models.Session{RenewAt: 1000, ValidUntil: 999999999999, UserId: 3}
	dbInstance.SaveSession("sess-1", session)

	retrieved, ok := dbInstance.GetSession("sess-1")
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, retrieved.UserId, 3)
	test.IsEqualInt(t, int(retrieved.RenewAt), 1000)

	_, ok = dbInstance.GetSession("nonexistent")
	test.IsEqualBool(t, ok, false)

	dbInstance.SaveSession("sess-2", models.Session{RenewAt: 1, ValidUntil: 999999999999, UserId: 4})
	dbInstance.DeleteSession("sess-1")
	_, ok = dbInstance.GetSession("sess-1")
	test.IsEqualBool(t, ok, false)

	dbInstance.SaveSession("sess-3", models.Session{RenewAt: 1, ValidUntil: 999999999999, UserId: 4})
	dbInstance.DeleteAllSessionsByUser(4)
	_, ok = dbInstance.GetSession("sess-2")
	test.IsEqualBool(t, ok, false)
	_, ok = dbInstance.GetSession("sess-3")
	test.IsEqualBool(t, ok, false)

	// Expired sessions must be collected, valid ones kept
	dbInstance.SaveSession("sess-expired", models.Session{RenewAt: 1, ValidUntil: 1, UserId: 9})
	dbInstance.SaveSession("sess-valid", models.Session{RenewAt: 1, ValidUntil: 999999999999, UserId: 9})
	dbInstance.RunGarbageCollection()
	_, ok = dbInstance.GetSession("sess-expired")
	test.IsEqualBool(t, ok, false)
	_, ok = dbInstance.GetSession("sess-valid")
	test.IsEqualBool(t, ok, true)

	dbInstance.DeleteAllSessions()
	_, ok = dbInstance.GetSession("sess-valid")
	test.IsEqualBool(t, ok, false)
}

func TestUsers(t *testing.T) {
	testConfig(t)
	user := models.User{
		Name:          "alice@example.com",
		Password:      "hashed",
		Permissions:   models.UserPermissionAll,
		UserLevel:     models.UserLevelAdmin,
		LastOnline:    500,
		ResetPassword: true,
	}
	dbInstance.SaveUser(user, true)

	retrieved, ok := dbInstance.GetUserByName("alice@example.com")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, retrieved.Name, "alice@example.com")
	test.IsEqualBool(t, retrieved.ResetPassword, true)
	test.IsEqualInt(t, int(retrieved.UserLevel), int(models.UserLevelAdmin))

	byId, ok := dbInstance.GetUser(retrieved.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, byId.Name, "alice@example.com")

	_, ok = dbInstance.GetUserByName("nobody@example.com")
	test.IsEqualBool(t, ok, false)

	retrieved.Name = "alice2@example.com"
	retrieved.ResetPassword = false
	dbInstance.SaveUser(retrieved, false)
	updated, ok := dbInstance.GetUser(retrieved.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, updated.Name, "alice2@example.com")
	test.IsEqualBool(t, updated.ResetPassword, false)

	dbInstance.UpdateUserLastOnline(retrieved.Id)
	updated, _ = dbInstance.GetUser(retrieved.Id)
	test.IsEqualBool(t, updated.LastOnline > 500, true)

	// A generated Id must not collide with the explicitly written one above
	dbInstance.SaveUser(models.User{Name: "bob@example.com", UserLevel: models.UserLevelUser}, true)
	bob, ok := dbInstance.GetUserByName("bob@example.com")
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, bob.Id != retrieved.Id, true)

	test.IsEqualInt(t, len(dbInstance.GetAllUsers()), 2)

	dbInstance.DeleteUser(retrieved.Id)
	dbInstance.DeleteUser(bob.Id)
	test.IsEqualInt(t, len(dbInstance.GetAllUsers()), 0)
}

func TestEnd2EndInfo(t *testing.T) {
	testConfig(t)
	info := models.E2EInfoEncrypted{
		Version: 1,
		Nonce:   []byte{1, 2, 3},
		Content: []byte{4, 5, 6},
	}
	dbInstance.SaveEnd2EndInfo(info, 42)

	retrieved := dbInstance.GetEnd2EndInfo(42)
	test.IsEqualInt(t, retrieved.Version, 1)
	test.IsEqualBool(t, retrieved.HasBeenSetUp(), true)

	// Re-saving for the same user must update in place, not violate the unique constraint
	info.Version = 2
	dbInstance.SaveEnd2EndInfo(info, 42)
	retrieved = dbInstance.GetEnd2EndInfo(42)
	test.IsEqualInt(t, retrieved.Version, 2)

	empty := dbInstance.GetEnd2EndInfo(999)
	test.IsEqualBool(t, empty.HasBeenSetUp(), false)

	dbInstance.DeleteEnd2EndInfo(42)
	deleted := dbInstance.GetEnd2EndInfo(42)
	test.IsEqualBool(t, deleted.HasBeenSetUp(), false)
}

func TestFileRequests(t *testing.T) {
	testConfig(t)
	request := models.FileRequest{
		Id:           "req-1",
		Name:         "Client Upload",
		UserId:       2,
		MaxFiles:     10,
		MaxSize:      500,
		Expiry:       8888,
		CreationDate: 1111,
		ApiKey:       "key-req-1",
		Notes:        "please upload here",
	}
	dbInstance.SaveFileRequest(request)

	retrieved, ok := dbInstance.GetFileRequest("req-1")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, retrieved.Name, "Client Upload")
	test.IsEqualInt(t, retrieved.MaxFiles, 10)
	test.IsEqualInt(t, retrieved.MaxSize, 500)
	test.IsEqualString(t, retrieved.Notes, "please upload here")

	_, ok = dbInstance.GetFileRequest("")
	test.IsEqualBool(t, ok, false)
	_, ok = dbInstance.GetFileRequest("nonexistent")
	test.IsEqualBool(t, ok, false)

	request.Name = "Renamed Request"
	dbInstance.SaveFileRequest(request)
	retrieved, _ = dbInstance.GetFileRequest("req-1")
	test.IsEqualString(t, retrieved.Name, "Renamed Request")

	dbInstance.SaveFileRequest(models.FileRequest{Id: "req-2", CreationDate: 2222, ApiKey: "key-req-2"})
	all := dbInstance.GetAllFileRequests()
	test.IsEqualInt(t, len(all), 2)
	// Ordered by creation date descending
	test.IsEqualString(t, all[0].Id, "req-2")

	dbInstance.DeleteFileRequest(models.FileRequest{Id: ""})
	test.IsEqualInt(t, len(dbInstance.GetAllFileRequests()), 2)

	dbInstance.DeleteFileRequest(request)
	dbInstance.DeleteFileRequest(models.FileRequest{Id: "req-2"})
	test.IsEqualInt(t, len(dbInstance.GetAllFileRequests()), 0)
}

func TestStatistics(t *testing.T) {
	testConfig(t)
	test.IsEqualInt(t, int(dbInstance.GetStatTraffic()), 0)
	_, ok := dbInstance.GetTrafficSince()
	test.IsEqualBool(t, ok, false)

	dbInstance.SaveStatTraffic(1024)
	test.IsEqualInt(t, int(dbInstance.GetStatTraffic()), 1024)

	// Upsert on the unique Type column
	dbInstance.SaveStatTraffic(2048)
	test.IsEqualInt(t, int(dbInstance.GetStatTraffic()), 2048)

	dbInstance.SaveTrafficSince(1600000000)
	since, ok := dbInstance.GetTrafficSince()
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, int(since), 1600000000)

	dbInstance.SaveTrafficSince(1700000000)
	since, _ = dbInstance.GetTrafficSince()
	test.IsEqualInt(t, int(since), 1700000000)
}

// SQLite's INSERT OR REPLACE drops a row colliding on any unique constraint, so
// pointing a file at a new hotlink has to remove the old mapping as well.
func TestSaveHotlinkReplacesExistingFileMapping(t *testing.T) {
	testConfig(t)
	dbInstance.SaveHotlink(models.File{Id: "hlfile", HotlinkId: "hlold", Name: "a"})
	dbInstance.SaveHotlink(models.File{Id: "hlfile", HotlinkId: "hlnew", Name: "a"})

	_, ok := dbInstance.GetHotlink("hlold")
	test.IsEqualBool(t, ok, false)
	fileId, ok := dbInstance.GetHotlink("hlnew")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, fileId, "hlfile")
}

// Without a transaction the competing deletes both succeed and one insert then
// fails on the remaining unique constraint, which panics through helper.Check.
func TestSaveHotlinkConcurrent(t *testing.T) {
	testConfig(t)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			dbInstance.SaveHotlink(models.File{Id: "concurrentfile", HotlinkId: "hlc" + strconv.Itoa(n)})
		}(i)
	}
	wg.Wait()

	var count int
	row := dbInstance.postgresDb.QueryRow("SELECT COUNT(*) FROM Hotlinks WHERE FileId = $1", "concurrentfile")
	test.IsNil(t, row.Scan(&count))
	test.IsEqualInt(t, count, 1)
}

// A row written with an explicit Id does not advance the identity sequence, so the
// next generated user would reuse that Id unless the sequence is repaired.
func TestSaveUserGeneratedIdDoesNotCollide(t *testing.T) {
	testConfig(t)
	dbInstance.SaveUser(models.User{Id: 500, Name: "explicit@example.com", Password: "hash",
		Permissions: models.UserPermissionAll, UserLevel: models.UserLevelUser}, false)
	dbInstance.SaveUser(models.User{Name: "generated@example.com", Password: "hash",
		Permissions: models.UserPermissionAll, UserLevel: models.UserLevelUser}, true)

	explicit, ok := dbInstance.GetUserByName("explicit@example.com")
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, explicit.Id, 500)
	generated, ok := dbInstance.GetUserByName("generated@example.com")
	test.IsEqualBool(t, ok, true)
	if generated.Id == explicit.Id {
		t.Errorf("generated user reused the explicit id %d", explicit.Id)
	}
}

// TestColumnOrder checks the physical column order against the order the
// providers scan in. The queries select all columns and scan them positionally,
// so a column added in the middle of a table would map values onto the wrong
// struct fields instead of failing.
func TestColumnOrder(t *testing.T) {
	testConfig(t)
	expected := map[string][]string{
		"apikeys":        {"id", "friendlyname", "lastused", "permissions", "expiry", "issystemkey", "userid", "publicid", "uploadrequestid"},
		"uploadrequests": {"id", "name", "userid", "expiry", "maxfiles", "maxsize", "creation", "apikey", "note"},
		"users":          {"id", "name", "password", "permissions", "userlevel", "lastonline", "resetpassword"},
		"filemetadata": {"id", "name", "size", "sha1", "expireat", "sizebytes", "downloadsremaining", "downloadcount",
			"passwordhash", "hotlinkid", "contenttype", "awsbucket", "encryption", "unlimiteddownloads", "unlimitedtime",
			"userid", "uploaddate", "pendingdeletion", "uploadrequestid"},
	}
	for table, columns := range expected {
		rows, err := dbInstance.postgresDb.Query(`SELECT column_name FROM information_schema.columns
			WHERE table_name = $1 ORDER BY ordinal_position`, table)
		test.IsNil(t, err)
		actual := make([]string, 0)
		for rows.Next() {
			var name string
			err = rows.Scan(&name)
			test.IsNil(t, err)
			actual = append(actual, name)
		}
		test.IsNil(t, rows.Err())
		rows.Close()
		if len(actual) != len(columns) {
			t.Errorf("table %s has %d columns, expected %d", table, len(actual), len(columns))
			continue
		}
		for i, column := range columns {
			test.IsEqualString(t, actual[i], column)
		}
	}
}

func TestClose(t *testing.T) {
	config := testConfig(t)
	instance, err := New(config)
	test.IsNil(t, err)
	dropAllTables(t, instance)
	instance.Close()
}
