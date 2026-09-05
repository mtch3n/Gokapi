package database

import (
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/forceu/gokapi/internal/configuration/database/dbabstraction"
	"github.com/forceu/gokapi/internal/configuration/database/dbcache"
	"github.com/forceu/gokapi/internal/encryption"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/test"
)

var configSqlite = models.DbConnection{
	HostUrl: "./test/gokapi.sqlite",
	Type:    0, // dbabstraction.TypeSqlite
}

var configRedis = models.DbConnection{
	RedisPrefix: "test_",
	HostUrl:     test.PortRedisDatabase,
	Type:        1, // dbabstraction.TypeRedis
}

var mRedis *miniredis.Miniredis

var availableDatabases []dbabstraction.Database

func TestMain(m *testing.M) {

	mRedis = miniredis.NewMiniRedis()
	err := mRedis.StartAddr(test.PortRedisDatabase)
	if err != nil {
		log.Fatal("Could not start miniredis")
	}
	exitVal := m.Run()
	mRedis.Close()
	os.RemoveAll("./test/")
	os.Exit(exitVal)
}

func TestInit(t *testing.T) {
	availableDatabases = make([]dbabstraction.Database, 0)
	Connect(configRedis)
	availableDatabases = append(availableDatabases, db)
	Connect(configSqlite)
	availableDatabases = append(availableDatabases, db)
	defer test.ExpectPanic(t)
	Connect(models.DbConnection{Type: 2})
}

// shareDatabases is the provider list used by the share-recipient tests. It is
// separate from availableDatabases because the older cross-provider tests
// switch on db.GetType() with a `default: t.Fatal` and so accept exactly two
// providers; widening the shared list would break them for reasons unrelated
// to what they test.
//
// Postgres joins this list when GOKAPI_TEST_POSTGRES_URL is set. Without it,
// Postgres was the only provider never exercised by any cross-provider test,
// which is how a Postgres schema missing three columns, plus four queries
// using SQLite's "?" placeholders instead of "$n", reached a green test run.
//
// Start the database with:
//
//	docker run -d --name gokapi-test-pg -p 127.0.0.1:15432:5432 \
//	  -e POSTGRES_USER=gokapi -e POSTGRES_PASSWORD=testpw \
//	  -e POSTGRES_DB=gokapi_test postgres:17-alpine
//	export GOKAPI_TEST_POSTGRES_URL="postgres://gokapi:testpw@127.0.0.1:15432/gokapi_test?sslmode=disable"
func shareDatabases(t *testing.T) []dbabstraction.Database {
	t.Helper()
	result := append([]dbabstraction.Database{}, availableDatabases...)

	url := os.Getenv("GOKAPI_TEST_POSTGRES_URL")
	if url == "" {
		t.Log("GOKAPI_TEST_POSTGRES_URL is not set, the Postgres provider is not covered by this run")
		return result
	}
	config, err := ParseUrl(url, false)
	if err != nil {
		t.Fatalf("GOKAPI_TEST_POSTGRES_URL is not a valid connection string: %v", err)
	}
	previous := db
	Connect(config)
	postgresDb := db
	db = previous
	return append(result, postgresDb)
}

// runShareTypes runs the function against every provider that implements the
// share tables, leaving each one clean afterwards so ordering between tests
// cannot matter.
func runShareTypes(t *testing.T, functionToRun func()) {
	t.Helper()
	previous := db
	defer func() { db = previous }()
	for _, database := range shareDatabases(t) {
		db = database
		for _, recipient := range GetAllShareRecipients() {
			DeleteShareRecipient(recipient.Id)
		}
		functionToRun()
		for _, recipient := range GetAllShareRecipients() {
			DeleteShareRecipient(recipient.Id)
		}
	}
}

func TestApiKeys(t *testing.T) {
	runAllTypesCompareOutput(t, func() any { return GetAllApiKeys() }, map[string]models.ApiKey{})
	newApiKey := models.ApiKey{
		Id:           "test",
		FriendlyName: "testKey",
		PublicId:     "wfwefewwfefwe",
		LastUsed:     1000,
		Permissions:  10,
	}
	runAllTypesNoOutput(t, func() { SaveApiKey(newApiKey) })
	runAllTypesCompareTwoOutputs(t, func() (any, any) {
		return GetApiKey("test")
	}, newApiKey, true)
	newApiKey.LastUsed = 2000
	runAllTypesNoOutput(t, func() {
		dbcache.Init()
		UpdateTimeApiKey(newApiKey)
	})
	runAllTypesCompareOutput(t, func() any { return GetAllApiKeys() }, map[string]models.ApiKey{"test": newApiKey})
	runAllTypesNoOutput(t, func() { DeleteApiKey("test") })
	runAllTypesCompareTwoOutputs(t, func() (any, any) {
		return GetApiKey("test")
	}, models.ApiKey{}, false)

	runAllTypesNoOutput(t, func() {
		SaveApiKey(models.ApiKey{
			Id:       "publicTest",
			PublicId: "publicId",
		})
	})
	runAllTypesCompareOutput(t, func() any {
		_, ok := GetApiKey("publicTest")
		return ok
	}, true)
	runAllTypesCompareOutput(t, func() any {
		_, ok := GetApiKeyByPublicKey("publicTest")
		return ok
	}, false)
	runAllTypesCompareOutput(t, func() any {
		_, ok := GetApiKey("publicId")
		return ok
	}, false)
	runAllTypesCompareTwoOutputs(t, func() (any, any) {
		return GetApiKeyByPublicKey("publicId")
	}, "publicTest", true)
}

func TestE2E(t *testing.T) {
	input := models.E2EInfoEncrypted{
		Version:        1,
		Nonce:          []byte("test"),
		Content:        []byte("test2"),
		AvailableFiles: []string{"should", "not", "be", "saved"},
	}
	runAllTypesNoOutput(t, func() { SaveEnd2EndInfo(input, 3) })
	input.AvailableFiles = nil
	runAllTypesCompareOutput(t, func() any { return GetEnd2EndInfo(3) }, input)
	runAllTypesNoOutput(t, func() { DeleteEnd2EndInfo(3) })
	runAllTypesCompareOutput(t, func() any { return GetEnd2EndInfo(3) }, models.E2EInfoEncrypted{})
}

func TestSessions(t *testing.T) {
	runAllTypesCompareTwoOutputs(t, func() (any, any) { return GetSession("newsession") }, models.Session{}, false)
	input := models.Session{
		RenewAt:    time.Now().Add(10 * time.Second).Unix(),
		ValidUntil: time.Now().Add(20 * time.Second).Unix(),
	}
	runAllTypesNoOutput(t, func() { SaveSession("newsession", input) })
	runAllTypesCompareTwoOutputs(t, func() (any, any) { return GetSession("newsession") }, input, true)
	runAllTypesNoOutput(t, func() { DeleteSession("newsession") })
	runAllTypesCompareTwoOutputs(t, func() (any, any) { return GetSession("newsession") }, models.Session{}, false)
	runAllTypesNoOutput(t, func() { SaveSession("newsession", input) })
	runAllTypesCompareTwoOutputs(t, func() (any, any) { return GetSession("newsession") }, input, true)
	runAllTypesNoOutput(t, func() { DeleteAllSessions() })
	runAllTypesCompareTwoOutputs(t, func() (any, any) { return GetSession("newsession") }, models.Session{}, false)

	runAllTypesNoOutput(t, func() {
		SaveSession("session1", models.Session{
			RenewAt:    2147483645,
			ValidUntil: 2147483645,
			UserId:     20,
		})
		SaveSession("session2", models.Session{
			RenewAt:    2147483645,
			ValidUntil: 2147483645,
			UserId:     20,
		})
		SaveSession("session3", models.Session{
			RenewAt:    2147483645,
			ValidUntil: 2147483645,
			UserId:     40,
		})
	})

	runAllTypesCompareOutput(t, func() any {
		_, ok := GetSession("session1")
		return ok
	}, true)
	runAllTypesCompareOutput(t, func() any {
		_, ok := GetSession("session2")
		return ok
	}, true)
	runAllTypesCompareOutput(t, func() any {
		_, ok := GetSession("session3")
		return ok
	}, true)
	runAllTypesNoOutput(t, func() {
		DeleteAllSessionsByUser(20)
	})
	runAllTypesCompareOutput(t, func() any {
		_, ok := GetSession("session1")
		return ok
	}, false)
	runAllTypesCompareOutput(t, func() any {
		_, ok := GetSession("session2")
		return ok
	}, false)
	runAllTypesCompareOutput(t, func() any {
		_, ok := GetSession("session3")
		return ok
	}, true)
}

func TestHotlinks(t *testing.T) {
	runAllTypesCompareTwoOutputs(t, func() (any, any) { return GetHotlink("newhotlink") }, "", false)
	newFile := models.File{Id: "testfile",
		HotlinkId: "newhotlink"}
	runAllTypesNoOutput(t, func() { SaveHotlink(newFile) })
	runAllTypesCompareTwoOutputs(t, func() (any, any) { return GetHotlink("newhotlink") }, "testfile", true)
	runAllTypesCompareOutput(t, func() any { return GetAllHotlinks() }, []string{"newhotlink"})
	runAllTypesNoOutput(t, func() { DeleteHotlink("newhotlink") })
	runAllTypesCompareOutput(t, func() any { return GetAllHotlinks() }, []string{})
}

func TestMetaData(t *testing.T) {
	runAllTypesCompareOutput(t, func() any { return GetAllMetadata() }, map[string]models.File{})
	runAllTypesCompareTwoOutputs(t, func() (any, any) { return GetMetaDataById("testid") }, models.File{}, false)
	file := models.File{
		Id:                 "testid",
		Name:               "Testname",
		Size:               "3Kb",
		SHA1:               "12345556",
		PasswordHash:       "sfffwefwe",
		HotlinkId:          "hotlink",
		ContentType:        "none",
		AwsBucket:          "aws1",
		ExpireAt:           time.Now().Add(10 * time.Second).Unix(),
		PendingDeletion:    time.Now().Add(8 * time.Second).Unix(),
		UploadDate:         time.Now().Unix(),
		SizeBytes:          3 * 1024,
		DownloadsRemaining: 2,
		DownloadCount:      5,
		Encryption: models.EncryptionInfo{
			IsEncrypted:         true,
			IsEndToEndEncrypted: true,
			DecryptionKey:       []byte("dekey"),
			Nonce:               []byte("nonce"),
		},
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		DisposedAt:         time.Now().Add(-time.Hour).Unix(),
		DisposalReason:     models.DisposalReasonExpired,
	}
	runAllTypesNoOutput(t, func() { SaveMetaData(file) })
	runAllTypesCompareOutput(t, func() any {
		result, _ := GetMetaDataById(file.Id)
		return result.DownloadsRemaining
	}, 2)
	// NameEncryptedRaw is populated only on a read (see models.File.NameEncryptedRaw), so the
	// hand-built expected File never carries it; stripped from the read results below so these
	// comparisons stay about the fields the test actually cares about.
	runAllTypesCompareTwoOutputs(t, func() (any, any) {
		result, ok := GetMetaDataById("testid")
		return withoutNameEncryptedRaw(result), ok
	}, file, true)
	runAllTypesCompareOutput(t, func() any { return mapWithoutNameEncryptedRaw(GetAllMetadata()) }, map[string]models.File{"testid": file})
	runAllTypesNoOutput(t, func() { DeleteMetaData("testid") })
	runAllTypesCompareOutput(t, func() any { return GetAllMetadata() }, map[string]models.File{})
	runAllTypesCompareTwoOutputs(t, func() (any, any) { return GetMetaDataById("testid") }, models.File{}, false)

	increasedDownload := file
	increasedDownload.DownloadCount = increasedDownload.DownloadCount + 1

	runAllTypesCompareTwoOutputs(t, func() (any, any) {
		SaveMetaData(file)
		IncreaseDownloadCount(file.Id)
		result, ok := GetMetaDataById(file.Id)
		return withoutNameEncryptedRaw(result), ok
	}, increasedDownload, true)

	// Every granted call spends: one off DownloadsRemaining, one onto DownloadCount, and the
	// window stamped for the disposal delay to read later.
	acquiredAt := time.Now().Unix()
	increasedDownload.DownloadCount = increasedDownload.DownloadCount + 1
	increasedDownload.DownloadsRemaining = increasedDownload.DownloadsRemaining - 1
	increasedDownload.WindowOpenedAt = acquiredAt

	runAllTypesCompareTwoOutputs(t, func() (any, any) {
		test.IsEqualBool(t, AcquireDownload(file.Id, acquiredAt), true)
		result, ok := GetMetaDataById(file.Id)
		return withoutNameEncryptedRaw(result), ok
	}, increasedDownload, true)
	runAllTypesNoOutput(t, func() { DeleteMetaData(file.Id) })
}

// withoutNameEncryptedRaw clears models.File.NameEncryptedRaw, which is populated only on a read
// and therefore never present on a hand-built expected File, so tests that compare a read result
// against a literal can ignore it.
func withoutNameEncryptedRaw(file models.File) models.File {
	file.NameEncryptedRaw = nil
	return file
}

// mapWithoutNameEncryptedRaw applies withoutNameEncryptedRaw to every value in the map.
func mapWithoutNameEncryptedRaw(files map[string]models.File) map[string]models.File {
	result := make(map[string]models.File, len(files))
	for id, file := range files {
		result[id] = withoutNameEncryptedRaw(file)
	}
	return result
}

func TestUsers(t *testing.T) {
	runAllTypesCompareOutput(t, func() any { return len(GetAllUsers()) }, 0)
	user := models.User{
		Id:            1000,
		Name:          "test2",
		Permissions:   models.UserPermissionNone,
		UserLevel:     models.UserLevelAdmin,
		LastOnline:    1338,
		Password:      "1234568",
		ResetPassword: true,
	}
	runAllTypesNoOutput(t, func() { SaveUser(user, true) })
	user.Id = 1
	runAllTypesCompareTwoOutputs(t, func() (any, any) {
		return GetUser(1)
	}, user, true)
	runAllTypesCompareOutput(t, func() any { return len(GetAllUsers()) }, 1)
	user.Name = "test3"
	runAllTypesNoOutput(t, func() { SaveUser(user, false) })
	runAllTypesCompareOutput(t, func() any { return len(GetAllUsers()) }, 1)
	runAllTypesCompareTwoOutputs(t, func() (any, any) {
		return GetUserByName("test3")
	}, user, true)
	runAllTypesCompareTwoOutputs(t, func() (any, any) {
		return GetUserByName("TEST3")
	}, user, true)
	user.Name = "test4"
	runAllTypesNoOutput(t, func() { SaveUser(user, true) })
	var allUsersSqlite []models.User
	var allUsersRedis []models.User
	runAllTypesCompareOutput(t, func() any {
		allUsers := GetAllUsers()
		switch db.GetType() {
		case dbabstraction.TypeSqlite:
			allUsersSqlite = allUsers
		case dbabstraction.TypeRedis:
			allUsersRedis = allUsers
		default:
			t.Fatal("Unrecognized database type")
		}
		return len(GetAllUsers())
	}, 2)
	test.IsEqual(t, allUsersSqlite, allUsersRedis)
	runAllTypesNoOutput(t, func() {
		dbcache.Init()
		UpdateUserLastOnline(1)
	})
	runAllTypesCompareTwoOutputs(t, func() (any, any) {
		retrievedUser, ok := GetUser(1)
		isUpdated := time.Now().Unix()-retrievedUser.LastOnline < 5 && time.Now().Unix()-retrievedUser.LastOnline > -1
		return isUpdated, ok
	}, true, true)
	runAllTypesNoOutput(t, func() { DeleteUser(1) })
	runAllTypesCompareOutput(t, func() any {
		_, ok := GetUser(1)
		return ok
	}, false)

	user.Id = 10
	user.Name = "TEST5"
	runAllTypesNoOutput(t, func() { SaveUser(user, false) })
	runAllTypesCompareOutput(t, func() any {
		retrievedUser, _ := GetUser(10)
		return retrievedUser.Name
	}, "test5")

	runAllTypesCompareOutput(t, func() any {
		_, ok := GetSuperAdmin()
		return ok
	}, false)

	runAllTypesCompareOutput(t, func() any {
		err := EditSuperAdmin("user", "password")
		return err == nil
	}, false)

	runAllTypesNoOutput(t, func() {
		users := GetAllUsers()
		for _, rUser := range users {
			DeleteUser(rUser.Id)
		}
	})
	runAllTypesCompareOutput(t, func() any { return len(GetAllUsers()) }, 0)

	runAllTypesCompareOutput(t, func() any {
		return EditSuperAdmin("username", "pwhash")
	}, nil)
	runAllTypesCompareOutput(t, func() any {
		admin, ok := GetSuperAdmin()
		test.IsEqualInt(t, int(admin.Permissions), int(models.UserPermissionAll))
		test.IsEqualInt(t, int(admin.UserLevel), int(models.UserLevelSuperAdmin))
		test.IsEqualString(t, admin.Name, "username")
		test.IsEqualString(t, admin.Password, "pwhash")
		// A super admin row created with an empty/unset AuthProvider is exactly the row that let
		// a Google login for this email take the account over with no password, since the OAuth
		// allow-list only accepts AuthProvider == "google" (see authentication.getOrCreateUser).
		test.IsEqualString(t, admin.AuthProvider, models.AuthProviderInternal)
		return ok
	}, true)

	runAllTypesNoOutput(t, func() {
		err := EditSuperAdmin("username2", "")
		test.IsNil(t, err)
		admin, ok := GetSuperAdmin()
		test.IsEqualBool(t, ok, true)
		test.IsEqualString(t, admin.Name, "username2")
		test.IsEqualString(t, admin.Password, "pwhash")
	})
	runAllTypesNoOutput(t, func() {
		err := EditSuperAdmin("", "pwhash2")
		test.IsNil(t, err)
		admin, ok := GetSuperAdmin()
		test.IsEqualBool(t, ok, true)
		test.IsEqualString(t, admin.Name, "username2")
		test.IsEqualString(t, admin.Password, "pwhash2")
	})

	user.Name = ""
	defer test.ExpectPanic(t)
	SaveUser(user, true)
}

// Runs against every available provider, so the SQLite tables and the Redis
// hash-plus-reverse-index have to agree on the same observable behaviour.
func TestShareRecipientsAndGrants(t *testing.T) {
	runShareTypes(t, func() {
		const file = models.ShareResourceFile
		const bundle = models.ShareResourceBundle

		// A resource with no grants is unrestricted. This is the path every
		// share that existed before the feature takes.
		test.IsEqualBool(t, IsShareRestricted(file, "res-none"), false)

		// Email is normalised on the way in, so the same mailbox typed with
		// different casing is one recipient, not several.
		id := SaveShareRecipient(models.ShareRecipient{Email: "  Alice@Example.COM ", CreatedAt: 100})
		test.IsEqualBool(t, id > 0, true)
		alice, ok := GetShareRecipientByEmail("ALICE@example.com")
		test.IsEqualBool(t, ok, true)
		test.IsEqualString(t, alice.Email, "alice@example.com")
		test.IsEqualInt(t, alice.Id, id)

		bobId := SaveShareRecipient(models.ShareRecipient{Email: "bob@example.com", CreatedAt: 100})
		_, ok = GetShareRecipientByEmail("nobody@example.com")
		test.IsEqualBool(t, ok, false)

		SetShareGrants(file, "res-a", []int{id, bobId}, 7, 0)
		test.IsEqualInt(t, len(GetShareGrants(file, "res-a")), 2)
		test.IsEqualBool(t, IsShareRestricted(file, "res-a"), true)
		test.IsEqualBool(t, HasShareGrant(file, "res-a", id), true)
		test.IsEqualBool(t, HasShareGrant(file, "res-a", 9999), false)

		// grantedBy is recorded, since the audit question is "who gave this
		// person access".
		test.IsEqualInt(t, GetShareGrants(file, "res-a")[0].GrantedBy, 7)

		// The resource type is part of the identity: a bundle sharing an ID
		// with a file must not inherit its grants.
		test.IsEqualBool(t, HasShareGrant(bundle, "res-a", id), false)

		// Replacing the list revokes, rather than merely adding.
		SetShareGrants(file, "res-a", []int{bobId}, 7, 0)
		test.IsEqualBool(t, HasShareGrant(file, "res-a", id), false)
		test.IsEqualBool(t, HasShareGrant(file, "res-a", bobId), true)

		// Duplicates collapse.
		SetShareGrants(file, "res-b", []int{bobId, bobId, bobId}, 7, 0)
		test.IsEqualInt(t, len(GetShareGrants(file, "res-b")), 1)
		test.IsEqualInt(t, len(GetShareGrantsForRecipient(bobId)), 2)

		// Blocking revokes at once without touching the grant rows, so the
		// audit trail of what was granted survives.
		bob, _ := GetShareRecipient(bobId)
		bob.IsBlocked = true
		SaveShareRecipient(bob)
		test.IsEqualBool(t, HasShareGrant(file, "res-a", bobId), false)
		test.IsEqualInt(t, len(GetShareGrants(file, "res-a")), 1)
		bob.IsBlocked = false
		SaveShareRecipient(bob)
		test.IsEqualBool(t, HasShareGrant(file, "res-a", bobId), true)

		// Clearing returns the resource to an anonymous access mode.
		SetShareGrants(file, "res-b", []int{}, 7, 0)
		test.IsEqualBool(t, IsShareRestricted(file, "res-b"), false)

		DeleteShareGrants(file, "res-a")
		test.IsEqualInt(t, len(GetShareGrants(file, "res-a")), 0)

		// Deleting a recipient removes them and every grant they held.
		SetShareGrants(file, "res-c", []int{bobId}, 7, 0)
		DeleteShareRecipient(bobId)
		_, ok = GetShareRecipient(bobId)
		test.IsEqualBool(t, ok, false)
		test.IsEqualBool(t, HasShareGrant(file, "res-c", bobId), false)

		DeleteShareRecipient(id)
		DeleteShareGrants(file, "res-c")
	})
}

// DeleteShareGrants must retire the resource's login tokens along with its
// grants: once the grant is gone a leftover token would still let its holder
// in, and only a hash is stored so nothing sensitive survives regardless.
// This is also the path the explicit "clear the recipient list" UI action
// takes, so clearing a list must kill outstanding mailed links, not just the
// grant rows.
func TestDeleteShareGrantsAlsoDeletesLoginTokens(t *testing.T) {
	runShareTypes(t, func() {
		const file = models.ShareResourceFile
		id := SaveShareRecipient(models.ShareRecipient{Email: "erin@example.com", CreatedAt: 1})

		SetShareGrants(file, "res-token-a", []int{id}, 1, 0)
		SaveShareLoginToken(models.ShareLoginToken{
			TokenHash: "token-a", RecipientId: id, ResourceType: file,
			ResourceId: "res-token-a", CreatedAt: 1, ExpiresAt: 999999999999})

		// Control: a different resource's grant and token must survive.
		SetShareGrants(file, "res-token-b", []int{id}, 1, 0)
		SaveShareLoginToken(models.ShareLoginToken{
			TokenHash: "token-b", RecipientId: id, ResourceType: file,
			ResourceId: "res-token-b", CreatedAt: 1, ExpiresAt: 999999999999})

		DeleteShareGrants(file, "res-token-a")

		test.IsEqualInt(t, len(GetShareGrants(file, "res-token-a")), 0)
		_, ok := GetShareLoginToken("token-a")
		test.IsEqualBool(t, ok, false)

		test.IsEqualInt(t, len(GetShareGrants(file, "res-token-b")), 1)
		_, ok = GetShareLoginToken("token-b")
		test.IsEqualBool(t, ok, true)

		// The recipient row is the address book entry and audit anchor: it
		// must not be touched by a grant/token cascade.
		_, ok = GetShareRecipient(id)
		test.IsEqualBool(t, ok, true)

		DeleteShareGrants(file, "res-token-b")
		DeleteShareRecipient(id)
	})
}

// DeleteFileBundle must cascade to the bundle's share grants and login
// tokens, so every caller (filebundle.Delete, cleanInvalidBundles) inherits
// the cleanup without having to call DeleteShareGrants itself.
func TestDeleteFileBundleCascadesShareGrants(t *testing.T) {
	runShareTypes(t, func() {
		const bundle = models.ShareResourceBundle
		id := SaveShareRecipient(models.ShareRecipient{Email: "frank@example.com", CreatedAt: 1})

		SetShareGrants(bundle, "bundle-a", []int{id}, 1, 0)
		SaveShareLoginToken(models.ShareLoginToken{
			TokenHash: "bundle-token-a", RecipientId: id, ResourceType: bundle,
			ResourceId: "bundle-a", CreatedAt: 1, ExpiresAt: 999999999999})

		// Control: another bundle's grant and token must not be touched.
		SetShareGrants(bundle, "bundle-b", []int{id}, 1, 0)
		SaveShareLoginToken(models.ShareLoginToken{
			TokenHash: "bundle-token-b", RecipientId: id, ResourceType: bundle,
			ResourceId: "bundle-b", CreatedAt: 1, ExpiresAt: 999999999999})

		DeleteFileBundle(models.FileBundle{Id: "bundle-a"})

		test.IsEqualInt(t, len(GetShareGrants(bundle, "bundle-a")), 0)
		_, ok := GetShareLoginToken("bundle-token-a")
		test.IsEqualBool(t, ok, false)

		test.IsEqualInt(t, len(GetShareGrants(bundle, "bundle-b")), 1)
		_, ok = GetShareLoginToken("bundle-token-b")
		test.IsEqualBool(t, ok, true)

		_, ok = GetShareRecipient(id)
		test.IsEqualBool(t, ok, true)

		DeleteShareGrants(bundle, "bundle-b")
		DeleteShareRecipient(id)
	})
}

// DeleteFileRequest must cascade the same way as DeleteFileBundle.
func TestDeleteFileRequestCascadesShareGrants(t *testing.T) {
	runShareTypes(t, func() {
		const request = models.ShareResourceFileRequest
		id := SaveShareRecipient(models.ShareRecipient{Email: "grace@example.com", CreatedAt: 1})

		SetShareGrants(request, "req-a", []int{id}, 1, 0)
		SaveShareLoginToken(models.ShareLoginToken{
			TokenHash: "req-token-a", RecipientId: id, ResourceType: request,
			ResourceId: "req-a", CreatedAt: 1, ExpiresAt: 999999999999})

		// Control: another request's grant and token must not be touched.
		SetShareGrants(request, "req-b", []int{id}, 1, 0)
		SaveShareLoginToken(models.ShareLoginToken{
			TokenHash: "req-token-b", RecipientId: id, ResourceType: request,
			ResourceId: "req-b", CreatedAt: 1, ExpiresAt: 999999999999})

		DeleteFileRequest(models.FileRequest{Id: "req-a"})

		test.IsEqualInt(t, len(GetShareGrants(request, "req-a")), 0)
		_, ok := GetShareLoginToken("req-token-a")
		test.IsEqualBool(t, ok, false)

		test.IsEqualInt(t, len(GetShareGrants(request, "req-b")), 1)
		_, ok = GetShareLoginToken("req-token-b")
		test.IsEqualBool(t, ok, true)

		_, ok = GetShareRecipient(id)
		test.IsEqualBool(t, ok, true)

		DeleteShareGrants(request, "req-b")
		DeleteShareRecipient(id)
	})
}

// DeleteMetaData is belt-and-braces: purgeFile/deleteFileHard in
// internal/storage already call DeleteShareGrants themselves before calling
// this, but every other caller of DeleteMetaData must not leave an orphaned,
// still-reachable grant behind either. Calling it twice on the same resource
// (as the purge path effectively does) must be a harmless no-op the second
// time, not a panic.
func TestDeleteMetaDataCascadesShareGrants(t *testing.T) {
	runShareTypes(t, func() {
		const file = models.ShareResourceFile
		id := SaveShareRecipient(models.ShareRecipient{Email: "henry@example.com", CreatedAt: 1})

		SetShareGrants(file, "file-a", []int{id}, 1, 0)
		SaveShareLoginToken(models.ShareLoginToken{
			TokenHash: "file-token-a", RecipientId: id, ResourceType: file,
			ResourceId: "file-a", CreatedAt: 1, ExpiresAt: 999999999999})

		// Control: another file's grant and token must not be touched.
		SetShareGrants(file, "file-b", []int{id}, 1, 0)
		SaveShareLoginToken(models.ShareLoginToken{
			TokenHash: "file-token-b", RecipientId: id, ResourceType: file,
			ResourceId: "file-b", CreatedAt: 1, ExpiresAt: 999999999999})

		DeleteMetaData("file-a")

		test.IsEqualInt(t, len(GetShareGrants(file, "file-a")), 0)
		_, ok := GetShareLoginToken("file-token-a")
		test.IsEqualBool(t, ok, false)

		test.IsEqualInt(t, len(GetShareGrants(file, "file-b")), 1)
		_, ok = GetShareLoginToken("file-token-b")
		test.IsEqualBool(t, ok, true)

		_, ok = GetShareRecipient(id)
		test.IsEqualBool(t, ok, true)

		DeleteMetaData("file-a")

		DeleteShareGrants(file, "file-b")
		DeleteShareRecipient(id)
	})
}

// The download allowance is per recipient, not per resource, so two recipients
// on the same file each get their own budget rather than racing for one pool.
// TestAcquireDownloadNeverGrantsFree proves at the facade level, across every database type,
// that AcquireDownload always spends and never grants for free.
//
// This test used to be TestAcquireDownloadWindow, and asserted the opposite of what it asserts
// now: that a second request arriving soon after the first was served without spending a second
// allowance. That expectation was deliberately inverted. The only thing the old free ride was
// keyed on was the resource id, which identifies nobody, so anyone holding the link could keep
// re-triggering it and a file capped at N downloads was in practice uncapped. Resuming a genuine
// interrupted transfer without paying twice is now the job of the signed session token checked in
// the webserver layer, which never reaches this call.
func TestAcquireDownloadNeverGrantsFree(t *testing.T) {
	runAllTypesNoOutput(t, func() {
		timeNow := time.Now().Unix()
		id := "windowed"
		SaveMetaData(models.File{Id: id, Name: id, DownloadsRemaining: 1})

		test.IsEqualBool(t, AcquireDownload(id, timeNow), true)

		// Immediately afterwards, well inside what used to be the leeway: refused, because the
		// single allowance has already been spent. Previously this was granted for free.
		test.IsEqualBool(t, AcquireDownload(id, timeNow+60), false)

		// The refusal wrote nothing: exactly one allowance spent, one download counted, and the
		// window still stamped at the one call that was granted.
		stored, ok := GetMetaDataById(id)
		test.IsEqualBool(t, ok, true)
		test.IsEqualInt(t, stored.DownloadsRemaining, 0)
		test.IsEqualInt(t, stored.DownloadCount, 1)
		test.IsEqualInt64(t, stored.WindowOpenedAt, timeNow)

		// A file that still has an allowance spends it and re-stamps the window, which the
		// disposal delay - not any grant decision - reads.
		SaveMetaData(models.File{Id: id, Name: id, DownloadsRemaining: 2, WindowOpenedAt: timeNow})
		test.IsEqualBool(t, AcquireDownload(id, timeNow+3601), true)
		stored, ok = GetMetaDataById(id)
		test.IsEqualBool(t, ok, true)
		test.IsEqualInt(t, stored.DownloadsRemaining, 1)
		test.IsEqualInt64(t, stored.WindowOpenedAt, timeNow+3601)

		DeleteMetaData(id)
	})
}

// TestAcquireDownloadGrantsExactlyOnce is the property this whole change exists to create: two
// consecutive calls on a file with one download left grant exactly once, and the file ends at
// DownloadsRemaining 0 with DownloadCount incremented exactly once. Asserted at the facade so it
// holds for every provider behind it.
func TestAcquireDownloadGrantsExactlyOnce(t *testing.T) {
	runAllTypesNoOutput(t, func() {
		timeNow := time.Now().Unix()
		id := "spendonce"
		SaveMetaData(models.File{Id: id, Name: id, DownloadsRemaining: 1})

		test.IsEqualBool(t, AcquireDownload(id, timeNow), true)
		test.IsEqualBool(t, AcquireDownload(id, timeNow), false)

		stored, ok := GetMetaDataById(id)
		test.IsEqualBool(t, ok, true)
		test.IsEqualInt(t, stored.DownloadsRemaining, 0)
		test.IsEqualInt(t, stored.DownloadCount, 1)

		DeleteMetaData(id)
	})
}

// TestAcquireBundleDownloadNeverGrantsFree is TestAcquireDownloadNeverGrantsFree for a folder.
// It was TestAcquireBundleDownloadWindow, and its middle assertion has been inverted for the same
// reason as that test's: a folder's id identifies nobody either, so the second visit now spends
// instead of riding free, and with a single allowance it is therefore refused.
func TestAcquireBundleDownloadNeverGrantsFree(t *testing.T) {
	runAllTypesNoOutput(t, func() {
		timeNow := time.Now().Unix()
		bundle := models.FileBundle{Id: "windowedbundle", Name: "windowedbundle", DownloadsRemaining: 1}
		SaveFileBundle(bundle)

		test.IsEqualBool(t, AcquireBundleDownload(bundle.Id, timeNow), true)
		test.IsEqualBool(t, AcquireBundleDownload(bundle.Id, timeNow+60), false)

		stored, ok := GetFileBundle(bundle.Id)
		test.IsEqualBool(t, ok, true)
		test.IsEqualInt(t, stored.DownloadsRemaining, 0)
		test.IsEqualInt64(t, stored.WindowOpenedAt, timeNow)

		test.IsEqualBool(t, AcquireBundleDownload(bundle.Id, timeNow+3601), false)

		DeleteFileBundle(bundle)
	})
}

// TestAcquireShareGrantDownloadNeverGrantsFree is TestAcquireDownloadNeverGrantsFree's recipient
// twin (leeway-session-token plan, D24), and asserted the opposite of what it asserts now: that a
// second request arriving soon after the first was served free because it landed inside the
// window the first opened. That expectation was deliberately inverted. Unlike AcquireDownload's
// window, this one was bound to an identity - one recipient's own grant row - so it was not the
// production hole the anonymous window was, and was deliberately left standing at first for that
// reason. It goes now because the download session token supersedes it and is stronger: both are
// scoped to one resource, but this window could not be revoked mid-window and could not tell a
// resume from a fresh request, where the token is re-checked against the grant on every use and
// can be revoked between one request and the next. Resuming a genuine interrupted transfer
// without paying twice is now the token's job, checked in the webserver layer, which never
// reaches this call.
func TestAcquireShareGrantDownloadNeverGrantsFree(t *testing.T) {
	const leeway = 3600
	runShareTypes(t, func() {
		const file = models.ShareResourceFile
		mona := SaveShareRecipient(models.ShareRecipient{Email: "mona@example.com", CreatedAt: 1})
		SetShareGrants(file, "res-window", []int{mona}, 1, 1)

		timeNow := time.Now().Unix()
		granted, opened := AcquireShareGrantDownload(file, "res-window", mona, timeNow, leeway)
		test.IsEqualBool(t, granted, true)
		test.IsEqualBool(t, opened, true)

		// Immediately afterwards, well inside what used to be the leeway: refused, because the
		// single allowance has already been spent. Previously this was granted for free, and
		// opened reported it.
		granted, opened = AcquireShareGrantDownload(file, "res-window", mona, timeNow+60, leeway)
		test.IsEqualBool(t, granted, false)
		test.IsEqualBool(t, opened, false)
		for _, grant := range GetShareGrants(file, "res-window") {
			test.IsEqualInt(t, grant.DownloadsUsed, 1)
		}

		DeleteShareGrants(file, "res-window")
		DeleteShareRecipient(mona)
	})
}

// acquireGrantDownload records one download against a recipient's allowance. leeway is passed as
// 0 for parity with the signature only - AcquireShareGrantDownload no longer grants a free ride
// inside any window regardless of what leeway is (D24), so every call here genuinely spends.
func acquireGrantDownload(resourceType int, resourceId string, recipientId int) bool {
	granted, _ := AcquireShareGrantDownload(resourceType, resourceId, recipientId, time.Now().Unix(), 0)
	return granted
}

// acquireGrantDownloadOn is acquireGrantDownload against a specific provider rather than the
// package-global one, for the migration test.
func acquireGrantDownloadOn(provider dbabstraction.Database, resourceType int, resourceId string, recipientId int) bool {
	granted, _ := provider.AcquireShareGrantDownload(resourceType, resourceId, recipientId, time.Now().Unix(), 0)
	return granted
}

func TestShareGrantDownloadCounter(t *testing.T) {
	runShareTypes(t, func() {
		const file = models.ShareResourceFile
		carol := SaveShareRecipient(models.ShareRecipient{Email: "carol@example.com", CreatedAt: 1})
		dave := SaveShareRecipient(models.ShareRecipient{Email: "dave@example.com", CreatedAt: 1})

		SetShareGrants(file, "res-count", []int{carol, dave}, 1, 2)

		// Each recipient spends only their own allowance.
		test.IsEqualBool(t, acquireGrantDownload(file, "res-count", carol), true)
		test.IsEqualBool(t, acquireGrantDownload(file, "res-count", carol), true)
		// Carol is now exhausted, and the database refuses rather than going
		// past the limit.
		test.IsEqualBool(t, acquireGrantDownload(file, "res-count", carol), false)
		// Dave is untouched by Carol spending hers.
		test.IsEqualBool(t, acquireGrantDownload(file, "res-count", dave), true)

		for _, grant := range GetShareGrants(file, "res-count") {
			if grant.RecipientId == carol {
				test.IsEqualInt(t, grant.DownloadsUsed, 2)
				test.IsEqualBool(t, grant.IsExhausted(time.Now().Unix(), 0), true)
				test.IsEqualBool(t, grant.LastDownloadAt > 0, true)
			}
			if grant.RecipientId == dave {
				test.IsEqualInt(t, grant.DownloadsUsed, 1)
				test.IsEqualBool(t, grant.IsExhausted(time.Now().Unix(), 0), false)
			}
		}

		// An allowance of 0 means unlimited.
		SetShareGrants(file, "res-unlimited", []int{carol}, 1, 0)
		for i := 0; i < 5; i++ {
			test.IsEqualBool(t, acquireGrantDownload(file, "res-unlimited", carol), true)
		}

		// A recipient with no grant is refused.
		test.IsEqualBool(t, acquireGrantDownload(file, "res-count", 4242), false)

		DeleteShareRecipient(carol)
		DeleteShareRecipient(dave)
		DeleteShareGrants(file, "res-count")
		DeleteShareGrants(file, "res-unlimited")
	})
}

// shareGrantFor returns the grant this recipient holds on the resource. The test fails if there
// is none, since every caller below is asserting something about a grant it has just created.
func shareGrantFor(t *testing.T, resourceType int, resourceId string, recipientId int) models.ShareGrant {
	t.Helper()
	for _, grant := range GetShareGrants(resourceType, resourceId) {
		if grant.RecipientId == recipientId {
			return grant
		}
	}
	t.Fatalf("recipient %d holds no grant on %s", recipientId, resourceId)
	return models.ShareGrant{}
}

// Editing a resource's recipient list must leave the recipients that stay on it exactly as they
// were. SetShareGrants is the only way to add or remove one, because the API replaces the whole
// list, so a destructive implementation refunds everybody already on the share every time a
// further address is typed in.
//
// The second call passes a different actor and a different allowance from the first, so a grant
// that was rewritten with the current arguments is visible even though both calls land in the
// same second. The counts are written as literals rather than derived from the allowance, so the
// test still says something if the allowance ever changes.
func TestSetShareGrantsKeepsExistingRecipientsProgress(t *testing.T) {
	runShareTypes(t, func() {
		const file = models.ShareResourceFile
		anna := SaveShareRecipient(models.ShareRecipient{Email: "anna@example.com", CreatedAt: 1})
		ben := SaveShareRecipient(models.ShareRecipient{Email: "ben@example.com", CreatedAt: 1})

		SetShareGrants(file, "res-keep", []int{anna}, 7, 3)
		test.IsEqualBool(t, acquireGrantDownload(file, "res-keep", anna), true)
		test.IsEqualBool(t, acquireGrantDownload(file, "res-keep", anna), true)
		before := shareGrantFor(t, file, "res-keep", anna)
		test.IsEqualInt(t, before.DownloadsUsed, 2)
		test.IsEqualBool(t, before.LastDownloadAt > 0, true)

		// The owner adds a second address.
		SetShareGrants(file, "res-keep", []int{anna, ben}, 9, 5)

		after := shareGrantFor(t, file, "res-keep", anna)
		test.IsEqual(t, after, before)
		test.IsEqualInt(t, after.DownloadsUsed, 2)
		test.IsEqualInt(t, after.DownloadsAllowed, 3)
		test.IsEqualInt(t, after.GrantedBy, 7)
		test.IsEqualInt64(t, after.LastDownloadAt, before.LastDownloadAt)
		test.IsEqualInt64(t, after.GrantedAt, before.GrantedAt)

		// Anna had one of her three left, so exactly one more download is granted and the next is
		// refused. Two more would mean the edit had refunded her.
		test.IsEqualBool(t, acquireGrantDownload(file, "res-keep", anna), true)
		test.IsEqualBool(t, acquireGrantDownload(file, "res-keep", anna), false)

		// Ben is new, so he gets the allowance and the actor this call resolved.
		newGrant := shareGrantFor(t, file, "res-keep", ben)
		test.IsEqualInt(t, newGrant.DownloadsUsed, 0)
		test.IsEqualInt(t, newGrant.DownloadsAllowed, 5)
		test.IsEqualInt(t, newGrant.GrantedBy, 9)
		test.IsEqualInt64(t, newGrant.LastDownloadAt, 0)

		DeleteShareGrants(file, "res-keep")
		DeleteShareRecipient(anna)
		DeleteShareRecipient(ben)
	})
}

// A recipient who has spent everything they were given must stay spent. This is the worst of the
// refund cases: a resource is finished once its last recipient has taken their last download, so
// handing an exhausted recipient a fresh budget brings content that was already out of reach back
// within it.
func TestSetShareGrantsDoesNotRefundAnExhaustedRecipient(t *testing.T) {
	runShareTypes(t, func() {
		const file = models.ShareResourceFile
		anna := SaveShareRecipient(models.ShareRecipient{Email: "anna@example.com", CreatedAt: 1})
		ben := SaveShareRecipient(models.ShareRecipient{Email: "ben@example.com", CreatedAt: 1})

		SetShareGrants(file, "res-spent", []int{anna}, 7, 1)
		test.IsEqualBool(t, acquireGrantDownload(file, "res-spent", anna), true)
		test.IsEqualBool(t, acquireGrantDownload(file, "res-spent", anna), false)

		SetShareGrants(file, "res-spent", []int{anna, ben}, 7, 1)

		test.IsEqualBool(t, acquireGrantDownload(file, "res-spent", anna), false)
		spent := shareGrantFor(t, file, "res-spent", anna)
		test.IsEqualInt(t, spent.DownloadsUsed, 1)
		test.IsEqualBool(t, spent.IsExhausted(time.Now().Unix(), 0), true)
		// Ben, who is new, is not caught by Anna having finished.
		test.IsEqualBool(t, acquireGrantDownload(file, "res-spent", ben), true)

		DeleteShareGrants(file, "res-spent")
		DeleteShareRecipient(anna)
		DeleteShareRecipient(ben)
	})
}

// Taking one address off the list revokes that one and nothing else. Revocation stays immediate:
// the grant is gone, the reverse index no longer lists it, and the download is refused.
func TestSetShareGrantsRemovalLeavesTheOthersUntouched(t *testing.T) {
	runShareTypes(t, func() {
		const file = models.ShareResourceFile
		anna := SaveShareRecipient(models.ShareRecipient{Email: "anna@example.com", CreatedAt: 1})
		ben := SaveShareRecipient(models.ShareRecipient{Email: "ben@example.com", CreatedAt: 1})
		cara := SaveShareRecipient(models.ShareRecipient{Email: "cara@example.com", CreatedAt: 1})

		SetShareGrants(file, "res-remove", []int{anna, ben, cara}, 7, 3)
		test.IsEqualBool(t, acquireGrantDownload(file, "res-remove", anna), true)
		test.IsEqualBool(t, acquireGrantDownload(file, "res-remove", ben), true)
		test.IsEqualBool(t, acquireGrantDownload(file, "res-remove", ben), true)
		annaBefore := shareGrantFor(t, file, "res-remove", anna)
		benBefore := shareGrantFor(t, file, "res-remove", ben)

		SetShareGrants(file, "res-remove", []int{anna, ben}, 9, 5)

		test.IsEqualInt(t, len(GetShareGrants(file, "res-remove")), 2)
		test.IsEqual(t, shareGrantFor(t, file, "res-remove", anna), annaBefore)
		test.IsEqual(t, shareGrantFor(t, file, "res-remove", ben), benBefore)
		test.IsEqualInt(t, shareGrantFor(t, file, "res-remove", anna).DownloadsUsed, 1)
		test.IsEqualInt(t, shareGrantFor(t, file, "res-remove", ben).DownloadsUsed, 2)
		test.IsEqualInt(t, shareGrantFor(t, file, "res-remove", anna).DownloadsAllowed, 3)

		// Cara is revoked at once.
		test.IsEqualBool(t, HasShareGrant(file, "res-remove", cara), false)
		test.IsEqualBool(t, acquireGrantDownload(file, "res-remove", cara), false)
		test.IsEqualInt(t, len(GetShareGrantsForRecipient(cara)), 0)

		DeleteShareGrants(file, "res-remove")
		DeleteShareRecipient(anna)
		DeleteShareRecipient(ben)
		DeleteShareRecipient(cara)
	})
}

// Taking an address off the list and putting it back is a revocation followed by a new grant, so
// that recipient starts again from zero. Nothing of the old grant is kept across the removal: the
// row is what makes a resource restricted at all, so keeping a spent one alive to remember a
// count would leave a revoked person listed as a recipient of the share.
//
// It does mean an owner can deliberately refund someone by removing them and adding them back.
// That is a two-step act the owner chose, and it is the only way to reopen a share to someone who
// has finished with it. What was wrong before was that the refund happened to everyone, silently,
// as a side effect of typing in one more address.
func TestSetShareGrantsReAddedRecipientStartsFresh(t *testing.T) {
	runShareTypes(t, func() {
		const file = models.ShareResourceFile
		anna := SaveShareRecipient(models.ShareRecipient{Email: "anna@example.com", CreatedAt: 1})
		ben := SaveShareRecipient(models.ShareRecipient{Email: "ben@example.com", CreatedAt: 1})

		SetShareGrants(file, "res-readd", []int{anna, ben}, 7, 2)
		test.IsEqualBool(t, acquireGrantDownload(file, "res-readd", anna), true)
		test.IsEqualBool(t, acquireGrantDownload(file, "res-readd", anna), true)
		test.IsEqualBool(t, acquireGrantDownload(file, "res-readd", anna), false)
		test.IsEqualBool(t, acquireGrantDownload(file, "res-readd", ben), true)
		benBefore := shareGrantFor(t, file, "res-readd", ben)

		SetShareGrants(file, "res-readd", []int{ben}, 7, 2)
		test.IsEqualBool(t, HasShareGrant(file, "res-readd", anna), false)
		SetShareGrants(file, "res-readd", []int{ben, anna}, 7, 2)

		fresh := shareGrantFor(t, file, "res-readd", anna)
		test.IsEqualInt(t, fresh.DownloadsUsed, 0)
		test.IsEqualInt64(t, fresh.LastDownloadAt, 0)
		test.IsEqualBool(t, acquireGrantDownload(file, "res-readd", anna), true)

		// Ben never left the list, so neither edit touched him and he still has one of his two.
		test.IsEqual(t, shareGrantFor(t, file, "res-readd", ben), benBefore)
		test.IsEqualInt(t, shareGrantFor(t, file, "res-readd", ben).DownloadsUsed, 1)
		test.IsEqualBool(t, acquireGrantDownload(file, "res-readd", ben), true)
		test.IsEqualBool(t, acquireGrantDownload(file, "res-readd", ben), false)

		DeleteShareGrants(file, "res-readd")
		DeleteShareRecipient(anna)
		DeleteShareRecipient(ben)
	})
}

// TestGetAllShareGrants covers the one read that walks the whole grant table, which the callers
// resolving every file's access axes in one pass depend on - the owner's file list and the
// CleanUp sweep, which would otherwise read the grants of every file one at a time. Every
// provider must return grants across resources AND across resource types, since a file and a
// folder are stored under separate keys.
func TestGetAllShareGrants(t *testing.T) {
	runShareTypes(t, func() {
		erin := SaveShareRecipient(models.ShareRecipient{Email: "erin@example.com", CreatedAt: 1})
		frank := SaveShareRecipient(models.ShareRecipient{Email: "frank@example.com", CreatedAt: 1})

		SetShareGrants(models.ShareResourceFile, "res-all-file", []int{erin, frank}, 1, 3)
		SetShareGrants(models.ShareResourceBundle, "res-all-bundle", []int{erin}, 1, 5)

		allowanceByResource := make(map[string][]int)
		for _, grant := range GetAllShareGrants() {
			key := grant.ResourceId
			allowanceByResource[key] = append(allowanceByResource[key], grant.DownloadsAllowed)
		}
		test.IsEqualInt(t, len(allowanceByResource["res-all-file"]), 2)
		test.IsEqualInt(t, allowanceByResource["res-all-file"][0], 3)
		test.IsEqualInt(t, allowanceByResource["res-all-file"][1], 3)
		test.IsEqualInt(t, len(allowanceByResource["res-all-bundle"]), 1)
		test.IsEqualInt(t, allowanceByResource["res-all-bundle"][0], 5)

		DeleteShareGrants(models.ShareResourceFile, "res-all-file")
		DeleteShareGrants(models.ShareResourceBundle, "res-all-bundle")
		DeleteShareRecipient(erin)
		DeleteShareRecipient(frank)
	})
}

// The link is reusable by design: a single-use link would be burned by mail
// scanners such as Outlook Safe Links before the recipient ever clicked it,
// and the per-recipient download allowance already presumes repeat visits.
func TestShareLoginTokenIsReusable(t *testing.T) {
	runShareTypes(t, func() {
		token := models.ShareLoginToken{
			TokenHash:    "hash-reusable",
			RecipientId:  55,
			ResourceType: models.ShareResourceFile,
			ResourceId:   "res-token",
			CreatedAt:    1000,
			ExpiresAt:    2000,
		}
		SaveShareLoginToken(token)

		stored, ok := GetShareLoginToken("hash-reusable")
		test.IsEqualBool(t, ok, true)
		test.IsEqualInt64(t, stored.FirstUsedAt, 0)
		test.IsEqualBool(t, stored.IsRevoked, false)

		// Redemption records the FIRST use and leaves the link usable.
		MarkShareLoginTokenUsed("hash-reusable", 1500)
		stored, _ = GetShareLoginToken("hash-reusable")
		test.IsEqualInt64(t, stored.FirstUsedAt, 1500)
		test.IsEqualBool(t, stored.IsRevoked, false)

		// A later use does not overwrite the first, so the audit trail shows
		// when the link was actually collected.
		MarkShareLoginTokenUsed("hash-reusable", 1800)
		stored, _ = GetShareLoginToken("hash-reusable")
		test.IsEqualInt64(t, stored.FirstUsedAt, 1500)

		_, ok = GetShareLoginToken("no-such-hash")
		test.IsEqualBool(t, ok, false)
	})
}

// A resend must retire the previous link, or every resend would leave another
// live bearer credential sitting in an inbox.
func TestShareLoginTokenResend(t *testing.T) {
	runShareTypes(t, func() {
		const file = models.ShareResourceFile
		test.IsEqualInt64(t, GetLastShareLoginTokenTime(77, file, "res-resend"), 0)

		SaveShareLoginToken(models.ShareLoginToken{
			TokenHash: "resend-first", RecipientId: 77, ResourceType: file,
			ResourceId: "res-resend", CreatedAt: 5000, ExpiresAt: 9000})
		test.IsEqualInt64(t, GetLastShareLoginTokenTime(77, file, "res-resend"), 5000)

		SaveShareLoginToken(models.ShareLoginToken{
			TokenHash: "resend-second", RecipientId: 77, ResourceType: file,
			ResourceId: "res-resend", CreatedAt: 5100, ExpiresAt: 9000})
		test.IsEqualInt64(t, GetLastShareLoginTokenTime(77, file, "res-resend"), 5100)

		RevokeShareLoginTokens(77, file, "res-resend")
		first, _ := GetShareLoginToken("resend-first")
		test.IsEqualBool(t, first.IsRevoked, true)

		// A different resource is unaffected.
		test.IsEqualInt64(t, GetLastShareLoginTokenTime(77, file, "other"), 0)

		// Expiry sweeps the row, so the hash does not outlive the resource.
		CleanUpExpiredShareLoginTokens(10000)
		_, ok := GetShareLoginToken("resend-first")
		test.IsEqualBool(t, ok, false)
		_, ok = GetShareLoginToken("resend-second")
		test.IsEqualBool(t, ok, false)
	})
}

// Renaming a recipient must not leave the old address resolving to them.
// Redis keeps a separate email index, so it is the provider that can drift;
// the SQL providers update the column in place.
func TestShareRecipientEmailChangeDropsOldIndex(t *testing.T) {
	runShareTypes(t, func() {
		id := SaveShareRecipient(models.ShareRecipient{Email: "old@example.com", CreatedAt: 1})
		recipient, _ := GetShareRecipient(id)
		recipient.Email = "new@example.com"
		SaveShareRecipient(recipient)

		_, foundOld := GetShareRecipientByEmail("old@example.com")
		test.IsEqualBool(t, foundOld, false)

		moved, foundNew := GetShareRecipientByEmail("new@example.com")
		test.IsEqualBool(t, foundNew, true)
		test.IsEqualInt(t, moved.Id, id)

		DeleteShareRecipient(id)
	})
}

// Revoking a grant must not be undone by a download arriving at the same
// moment. This locks the Redis path in particular: an earlier read-then-
// increment version recreated the deleted grant hash with only a counter
// field, which then scanned as "unlimited downloads" and handed a revoked
// recipient unrestricted access.
func TestShareGrantDownloadCannotResurrectRevokedGrant(t *testing.T) {
	runShareTypes(t, func() {
		const file = models.ShareResourceFile
		id := SaveShareRecipient(models.ShareRecipient{Email: "revoked@example.com", CreatedAt: 1})
		SetShareGrants(file, "res-revoke", []int{id}, 1, 5)
		test.IsEqualBool(t, acquireGrantDownload(file, "res-revoke", id), true)

		DeleteShareGrants(file, "res-revoke")

		test.IsEqualBool(t, acquireGrantDownload(file, "res-revoke", id), false)
		test.IsEqualBool(t, HasShareGrant(file, "res-revoke", id), false)
		test.IsEqualBool(t, IsShareRestricted(file, "res-revoke"), false)
		test.IsEqualInt(t, len(GetShareGrants(file, "res-revoke")), 0)

		DeleteShareRecipient(id)
	})
}

// Replacing a recipient list must never leave the resource momentarily
// unrestricted, because an unrestricted resource reads as publicly
// downloadable. The observable requirement is that the resource is restricted
// before, during and after, whether the new list overlaps the old one or is
// disjoint from it.
func TestSetShareGrantsKeepsResourceRestricted(t *testing.T) {
	runShareTypes(t, func() {
		const file = models.ShareResourceFile
		first := SaveShareRecipient(models.ShareRecipient{Email: "first@example.com", CreatedAt: 1})
		second := SaveShareRecipient(models.ShareRecipient{Email: "second@example.com", CreatedAt: 1})

		SetShareGrants(file, "res-replace", []int{first}, 1, 2)
		test.IsEqualBool(t, IsShareRestricted(file, "res-replace"), true)
		test.IsEqualBool(t, acquireGrantDownload(file, "res-replace", first), true)

		// Replace with an overlapping list.
		SetShareGrants(file, "res-replace", []int{first, second}, 1, 2)
		test.IsEqualBool(t, IsShareRestricted(file, "res-replace"), true)
		test.IsEqualInt(t, len(GetShareGrants(file, "res-replace")), 2)
		for _, grant := range GetShareGrants(file, "res-replace") {
			// The recipient carried across the replacement keeps the download
			// she had already taken; the one added by it starts at zero. See
			// TestSetShareGrantsKeepsExistingRecipientsProgress.
			if grant.RecipientId == first {
				test.IsEqualInt(t, grant.DownloadsUsed, 1)
			} else {
				test.IsEqualInt(t, grant.DownloadsUsed, 0)
			}
			test.IsEqualInt(t, grant.DownloadsAllowed, 2)
		}

		// Replace with a disjoint list: the dropped recipient loses access,
		// and the resource never stops being restricted.
		SetShareGrants(file, "res-replace", []int{second}, 1, 2)
		test.IsEqualBool(t, IsShareRestricted(file, "res-replace"), true)
		test.IsEqualBool(t, HasShareGrant(file, "res-replace", first), false)
		test.IsEqualBool(t, acquireGrantDownload(file, "res-replace", first), false)
		test.IsEqualInt(t, len(GetShareGrantsForRecipient(first)), 0)

		DeleteShareGrants(file, "res-replace")
		DeleteShareRecipient(first)
		DeleteShareRecipient(second)
	})
}

// The first redemption is the one recorded, not the most recent, or the audit
// trail would say when the link was last touched rather than collected.
func TestMarkShareLoginTokenUsedRecordsFirstUseOnly(t *testing.T) {
	runShareTypes(t, func() {
		SaveShareLoginToken(models.ShareLoginToken{
			TokenHash: "first-use-hash", RecipientId: 3, ResourceType: models.ShareResourceFile,
			ResourceId: "res-first", CreatedAt: 100, ExpiresAt: 999999999999})

		MarkShareLoginTokenUsed("first-use-hash", 200)
		MarkShareLoginTokenUsed("first-use-hash", 300)

		stored, ok := GetShareLoginToken("first-use-hash")
		test.IsEqualBool(t, ok, true)
		test.IsEqualInt64(t, stored.FirstUsedAt, 200)

		// An unknown hash must be a no-op rather than creating a phantom row.
		MarkShareLoginTokenUsed("no-such-hash-at-all", 400)
		_, ok = GetShareLoginToken("no-such-hash-at-all")
		test.IsEqualBool(t, ok, false)
	})
}

// A provider migration must carry the recipient ACLs. Omitting them is a
// silent fail-open, not merely lost data: whether a resource is restricted is
// derived from having any grant at all, so a migrated database with no grants
// reports every previously identity-restricted file as anonymously
// downloadable.
func TestMigrateCarriesShareAccess(t *testing.T) {
	source, err := dbabstraction.GetNew(configSqlite)
	test.IsNil(t, err)
	const file = models.ShareResourceFile

	aliceId := source.SaveShareRecipient(models.ShareRecipient{Email: "m-alice@example.com", CreatedAt: 10})
	bobId := source.SaveShareRecipient(models.ShareRecipient{Email: "m-bob@example.com", CreatedAt: 11})
	source.SetShareGrants(file, "res-migrate", []int{aliceId, bobId}, 5, 4)
	test.IsEqualBool(t, acquireGrantDownloadOn(source, file, "res-migrate", aliceId), true)
	source.SaveShareLoginToken(models.ShareLoginToken{
		TokenHash: "migrate-token", RecipientId: aliceId, ResourceType: file,
		ResourceId: "res-migrate", CreatedAt: 12, ExpiresAt: 999999999999})
	source.Close()

	target := models.DbConnection{HostUrl: "./test/migrated.sqlite", Type: 0}
	Migrate(configSqlite, target)

	Connect(target)
	defer Connect(configSqlite)

	// The resource is still restricted, which is the property that matters.
	test.IsEqualBool(t, IsShareRestricted(file, "res-migrate"), true)
	test.IsEqualInt(t, len(GetShareGrants(file, "res-migrate")), 2)

	// Recipients are matched by email, because the destination assigns its own
	// IDs and reusing the source IDs would attach grants to whoever happened to
	// land on that number.
	alice, ok := GetShareRecipientByEmail("m-alice@example.com")
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, HasShareGrant(file, "res-migrate", alice.Id), true)

	// The allowance already spent is carried across, so a migration does not
	// hand everyone a fresh budget.
	for _, grant := range GetShareGrants(file, "res-migrate") {
		test.IsEqualInt(t, grant.DownloadsAllowed, 4)
		if grant.RecipientId == alice.Id {
			test.IsEqualInt(t, grant.DownloadsUsed, 1)
		}
	}

	// Live links come across too, remapped to the new recipient ID.
	token, ok := GetShareLoginToken("migrate-token")
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, token.RecipientId, alice.Id)
}

// Creating the same address twice must yield one recipient, not two. The SQL
// providers get this from UNIQUE(email); Redis has to claim the index key
// atomically or it produces an orphan whose grants nothing can reach.
func TestShareRecipientEmailIsUnique(t *testing.T) {
	runShareTypes(t, func() {
		first := SaveShareRecipient(models.ShareRecipient{Email: "dup@example.com", CreatedAt: 1})
		second := SaveShareRecipient(models.ShareRecipient{Email: "dup@example.com", CreatedAt: 2})
		test.IsEqualInt(t, second, first)
		test.IsEqualInt(t, len(GetAllShareRecipients()), 1)
	})
}

func TestUpgrade(t *testing.T) {
	runAllTypesNoOutput(t, func() { test.IsEqualBool(t, db.GetDbVersion() != 1, true) })
	runAllTypesNoOutput(t, func() { db.SetDbVersion(1) })
	runAllTypesNoOutput(t, func() { test.IsEqualInt(t, db.GetDbVersion(), 1) })
	// runAllTypesNoOutput(t, func() { Upgrade() })
	// runAllTypesNoOutput(t, func() { test.IsEqualInt(t, db.GetDbVersion(), db.GetSchemaVersion()) })
}

func TestRunGarbageCollection(t *testing.T) {
	runAllTypesNoOutput(t, func() { RunGarbageCollection() })
}

func TestClose(t *testing.T) {
	runAllTypesNoOutput(t, func() { Close() })
}

func runAllTypesNoOutput(t *testing.T, functionToRun func()) {
	t.Helper()
	for _, database := range availableDatabases {
		db = database
		functionToRun()
	}
}

func runAllTypesCompareOutput(t *testing.T, functionToRun func() any, expectedOutput any) {
	t.Helper()
	for _, database := range availableDatabases {
		db = database
		output := functionToRun()
		test.IsEqual(t, output, expectedOutput)
	}
}

func runAllTypesCompareTwoOutputs(t *testing.T, functionToRun func() (any, any), expectedOutput1, expectedOutput2 any) {
	t.Helper()
	for _, database := range availableDatabases {
		db = database
		output1, output2 := functionToRun()
		test.IsEqual(t, output1, expectedOutput1)
		test.IsEqual(t, output2, expectedOutput2)
	}
}

func TestParseUrl(t *testing.T) {
	expectedOutput := models.DbConnection{}
	output, err := ParseUrl("invalid", false)
	test.IsNotNil(t, err)
	test.IsEqual(t, output, expectedOutput)

	_, err = ParseUrl("", false)
	test.IsNotNil(t, err)
	_, err = ParseUrl("inv\r\nalid", false)
	test.IsNotNil(t, err)
	_, err = ParseUrl("", false)
	test.IsNotNil(t, err)

	expectedOutput = models.DbConnection{
		HostUrl: "./test",
		Type:    dbabstraction.TypeSqlite,
	}
	output, err = ParseUrl("sqlite://./test", false)
	test.IsNil(t, err)
	test.IsEqual(t, output, expectedOutput)

	// Postgres keeps the full DSN, since pgx consumes credentials and query parameters
	expectedOutput = models.DbConnection{
		HostUrl:  "postgres://user:pw@127.0.0.1:5432/gokapi?sslmode=require",
		Username: "user",
		Password: "pw",
		Type:     dbabstraction.TypePostgres,
	}
	output, err = ParseUrl("postgres://user:pw@127.0.0.1:5432/gokapi?sslmode=require", false)
	test.IsNil(t, err)
	test.IsEqual(t, output, expectedOutput)

	output, err = ParseUrl("postgresql://user@db.example.com:5432/gokapi", false)
	test.IsNil(t, err)
	test.IsEqualInt(t, output.Type, dbabstraction.TypePostgres)

	_, err = ParseUrl("sqlite:///invalid", true)
	test.IsNotNil(t, err)
	output, err = ParseUrl("sqlite:///invalid", false)
	test.IsNil(t, err)
	test.IsEqualString(t, output.HostUrl, "/invalid")

	expectedOutput = models.DbConnection{
		HostUrl:     "127.0.0.1:1234",
		RedisPrefix: "",
		Username:    "",
		Password:    "",
		RedisUseSsl: false,
		Type:        dbabstraction.TypeRedis,
	}
	output, err = ParseUrl("redis://127.0.0.1:1234", false)
	test.IsNil(t, err)
	test.IsEqual(t, output, expectedOutput)

	expectedOutput = models.DbConnection{
		HostUrl:     "127.0.0.1:1234",
		RedisPrefix: "tpref",
		Username:    "tuser",
		Password:    "tpw",
		RedisUseSsl: true,
		Type:        dbabstraction.TypeRedis,
	}
	output, err = ParseUrl("redis://tuser:tpw@127.0.0.1:1234/?ssl=true&prefix=tpref", false)
	test.IsNil(t, err)
	test.IsEqual(t, output, expectedOutput)
}

func TestMigration(t *testing.T) {
	configNew := models.DbConnection{
		RedisPrefix: "testmigrate_",
		HostUrl:     test.PortRedisDatabase,
		Type:        1, // dbabstraction.TypeRedis
	}
	dbOld, err := dbabstraction.GetNew(configSqlite)
	test.IsNil(t, err)
	testFile := models.File{Id: "file1234", HotlinkId: "hotlink123"}
	dbOld.SaveMetaData(testFile)
	dbOld.SaveHotlink(testFile)
	dbOld.SaveApiKey(models.ApiKey{Id: "api123"})
	dbOld.SaveHotlink(testFile)
	dbOld.Close()

	Migrate(configSqlite, configNew)

	dbNew, err := dbabstraction.GetNew(configNew)
	test.IsNil(t, err)
	_, ok := dbNew.GetHotlink("hotlink123")
	test.IsEqualBool(t, ok, true)
	_, ok = dbNew.GetApiKey("api123")
	test.IsEqualBool(t, ok, true)
	_, ok = dbNew.GetMetaDataById("file1234")
	test.IsEqualBool(t, ok, true)
}

// TestMigrationNormalizesEmptyAuthProvider verifies that migrating from a source below
// schema v9/v17 can yield a user with an empty AuthProvider, since Migrate's destination is only
// ever New()'d, never Upgrade()'d, so the v9/v17 AuthProvider backfill never runs on the copied
// rows. SaveUser's explicit column list bypasses the SQL DEFAULT, so without normalization the
// destination would end up with an AuthProvider of ” - which is accepted by neither the OAuth
// nor the header-auth login door - locking the user out with no recovery path. Migrate must
// normalize an empty AuthProvider to "internal" for every copied user.
func TestMigrationNormalizesEmptyAuthProvider(t *testing.T) {
	configOld := models.DbConnection{
		HostUrl: "./test/gokapi_authprovider_src.sqlite",
		Type:    0, // dbabstraction.TypeSqlite
	}
	configNew := models.DbConnection{
		RedisPrefix: "testmigrateauthprovider_",
		HostUrl:     test.PortRedisDatabase,
		Type:        1, // dbabstraction.TypeRedis
	}
	dbOld, err := dbabstraction.GetNew(configOld)
	test.IsNil(t, err)
	dbOld.SaveUser(models.User{Name: "legacyuser", AuthProvider: ""}, true)
	dbOld.Close()

	Migrate(configOld, configNew)

	dbNew, err := dbabstraction.GetNew(configNew)
	test.IsNil(t, err)
	migratedUser, ok := dbNew.GetUserByName("legacyuser")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, migratedUser.AuthProvider, models.AuthProviderInternal)
}

// TestMigratePreservesEncryptedFileName guards against a data-loss bug: cmd/gokapi/Main.go runs
// --migrate-db (handleDbMigration) before encryption.Init loads the master key, so on a source
// database where file names are encrypted, DecryptFileName finds no key during the whole copy and
// reports every name as "". SaveMetaData's fallback for an empty Name - which exists so a
// bookkeeping write made while sealed does not blank out a name - then looked the name up in the
// DESTINATION database, found nothing (it is freshly created), and wrote NULL. The migration
// reported success while silently destroying every filename. This reproduces exactly that
// ordering without needing a second process: simulate "no key available" the same way an
// unsealed Input-level instance does (see encryption.IsSealed), migrate, then restore the
// original key to verify the destination actually kept the name rather than losing it.
func TestMigratePreservesEncryptedFileName(t *testing.T) {
	defer encryption.Init(models.Configuration{Encryption: models.Encryption{Level: encryption.NoEncryption}})

	key, err := encryption.GetRandomCipher()
	test.IsNil(t, err)
	encryption.Init(models.Configuration{Encryption: models.Encryption{
		Level: encryption.FullEncryptionStored, Cipher: key}})

	const secretName = "confidential-merger-plan.docx"
	configOld := models.DbConnection{
		HostUrl: "./test/gokapi_encryptedname_src.sqlite",
		Type:    0, // dbabstraction.TypeSqlite
	}
	configNew := models.DbConnection{
		RedisPrefix: "testmigrateencname_",
		HostUrl:     test.PortRedisDatabase,
		Type:        1, // dbabstraction.TypeRedis
	}

	dbOld, err := dbabstraction.GetNew(configOld)
	test.IsNil(t, err)
	dbOld.SaveMetaData(models.File{Id: "encnamefile", Name: secretName, SHA1: "abc"})
	dbOld.Close()

	// Reproduce the master key not being loaded yet, exactly as it is not during --migrate-db.
	encryption.Init(models.Configuration{Encryption: models.Encryption{
		Level: encryption.FullEncryptionInput, Salt: "somesalt", Checksum: "somechecksum", ChecksumSalt: "somechecksumsalt"}})
	test.IsEqualBool(t, encryption.IsDecryptionAvailable(), false)

	Migrate(configOld, configNew)

	// Restore the original key so the migrated row can be verified.
	encryption.Init(models.Configuration{Encryption: models.Encryption{
		Level: encryption.FullEncryptionStored, Cipher: key}})

	dbNew, err := dbabstraction.GetNew(configNew)
	test.IsNil(t, err)
	migrated, ok := dbNew.GetMetaDataById("encnamefile")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, migrated.Name, secretName)
}

// TestDisposedMetaDataRoundTripsThroughRedis is the "genuinely unverified" item the task calls
// out by name: no redis provider file was touched to add DisposedAt/DisposalReason, so it only
// compiles because redigo's ScanStruct/AddFlat reflect over the `redis:"..."` struct tags -
// nothing proves those tags actually round-trip until something reads the values back through
// Redis. This targets the Redis provider directly (bypassing the cross-provider harness, which
// strips NameEncryptedRaw from its comparisons - see withoutNameEncryptedRaw) and checks the new
// fields together with NameEncryptedRaw in the same read, the combination storage.disposeFile
// actually produces: a disposed row whose name is still stored encrypted.
//
// Opens its own connection (a distinct prefix, so it cannot collide with any other test's keys)
// rather than reusing availableDatabases[0]/the shared db var: TestClose permanently closes both
// of those, and file order in this package runs this test after TestClose - see
// TestMigratePreservesEncryptedFileName just above, which does the same for the same reason.
func TestDisposedMetaDataRoundTripsThroughRedis(t *testing.T) {
	defer encryption.Init(models.Configuration{Encryption: models.Encryption{Level: encryption.NoEncryption}})
	cipher, err := encryption.GetRandomCipher()
	test.IsNil(t, err)
	encryption.Init(models.Configuration{Encryption: models.Encryption{
		Level: encryption.FullEncryptionStored, Cipher: cipher}})

	dbRedis, err := dbabstraction.GetNew(models.DbConnection{
		RedisPrefix: "testdisposedredis_",
		HostUrl:     test.PortRedisDatabase,
		Type:        1, // dbabstraction.TypeRedis
	})
	test.IsNil(t, err)
	defer dbRedis.Close()

	const secretName = "redis-disposed-name.pdf"
	const fileId = "redisdisposedtest"
	dbRedis.SaveMetaData(models.File{
		Id:                 fileId,
		Name:               secretName,
		SHA1:               "", // disposal clears this
		DisposedAt:         1750000000,
		DisposalReason:     models.DisposalReasonExpired,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
	})

	stored, ok := dbRedis.GetMetaDataById(fileId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt64(t, stored.DisposedAt, 1750000000)
	test.IsEqualInt(t, stored.DisposalReason, models.DisposalReasonExpired)
	test.IsEqualString(t, stored.Name, secretName)
	test.IsEqualBool(t, len(stored.NameEncryptedRaw) > 0, true)

	all := dbRedis.GetAllMetadata()
	fromAll, found := all[fileId]
	test.IsEqualBool(t, found, true)
	test.IsEqualInt64(t, fromAll.DisposedAt, 1750000000)
	test.IsEqualInt(t, fromAll.DisposalReason, models.DisposalReasonExpired)
	test.IsEqualString(t, fromAll.Name, secretName)
}

func TestRedactUrl(t *testing.T) {
	// A Postgres DSN carries the password, so it must never be logged verbatim
	redacted := RedactUrl("postgres://user:hunter2@db.example.com:5432/gokapi?sslmode=require")
	test.IsEqualBool(t, strings.Contains(redacted, "hunter2"), false)
	test.IsEqualBool(t, strings.Contains(redacted, "db.example.com"), true)

	// URLs without credentials are returned unchanged
	test.IsEqualString(t, RedactUrl("sqlite://./data/gokapi.sqlite"), "sqlite://./data/gokapi.sqlite")
	test.IsEqualString(t, RedactUrl("redis://127.0.0.1:6379"), "redis://127.0.0.1:6379")
	test.IsEqualString(t, RedactUrl("not a url at all"), "not a url at all")
}
