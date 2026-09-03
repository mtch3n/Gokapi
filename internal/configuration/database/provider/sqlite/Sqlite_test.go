//go:build test

package sqlite

import (
	"bytes"
	"math"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/encryption"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/test"
)

var config = models.DbConnection{
	HostUrl: "./test/newfolder/gokapi.sqlite",
	Type:    0, // dbabstraction.TypeSqlite
}
var configUpgrade = models.DbConnection{
	HostUrl: "./test/newfolder/gokapi_old.sqlite",
	Type:    0, // dbabstraction.TypeSqlite
}

func TestMain(m *testing.M) {
	_ = os.Mkdir("test", 0777)
	exitVal := m.Run()
	_ = os.RemoveAll("test")
	os.Exit(exitVal)
}

var dbInstance DatabaseProvider

func TestInit(t *testing.T) {
	instance, err := New(config)
	test.IsNil(t, err)
	test.FolderExists(t, "./test/newfolder")
	instance.Close()
	err = os.WriteFile("./test/newfolder/gokapi2.sqlite", []byte("invalid"), 0700)
	test.IsNil(t, err)
	instance, err = New(models.DbConnection{
		HostUrl: "./test/newfolder/gokapi2.sqlite",
		Type:    0, // dbabstraction.TypeSqlite
	})
	test.IsNotNil(t, err)
	_, err = New(models.DbConnection{
		HostUrl: "",
		Type:    0, // dbabstraction.TypeSqlite
	})
	test.IsNotNil(t, err)
}

func TestClose(t *testing.T) {
	instance, err := New(config)
	test.IsNil(t, err)
	instance.Close()
	instance, err = New(config)
	test.IsNil(t, err)
	dbInstance = instance
}

func TestDatabaseProvider_GetDbVersion(t *testing.T) {
	version := dbInstance.GetDbVersion()
	test.IsEqualInt(t, version, DatabaseSchemeVersion)
	dbInstance.SetDbVersion(99)
	test.IsEqualInt(t, dbInstance.GetDbVersion(), 99)
	dbInstance.SetDbVersion(DatabaseSchemeVersion)
}

func TestDatabaseProvider_GetSchemaVersion(t *testing.T) {
	test.IsEqualInt(t, dbInstance.GetSchemaVersion(), DatabaseSchemeVersion)
}

func TestMetaData(t *testing.T) {
	files := dbInstance.GetAllMetadata()
	test.IsEqualInt(t, len(files), 0)

	dbInstance.SaveMetaData(models.File{Id: "testfile", Name: "test.txt", ExpireAt: time.Now().Add(time.Hour).Unix()})
	files = dbInstance.GetAllMetadata()
	test.IsEqualInt(t, len(files), 1)
	test.IsEqualString(t, files["testfile"].Name, "test.txt")

	file, ok := dbInstance.GetMetaDataById("testfile")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, file.Id, "testfile")
	_, ok = dbInstance.GetMetaDataById("invalid")
	test.IsEqualBool(t, ok, false)

	test.IsEqualInt(t, len(dbInstance.GetAllMetadata()), 1)
	dbInstance.DeleteMetaData("invalid")
	test.IsEqualInt(t, len(dbInstance.GetAllMetadata()), 1)

	test.IsEqualBool(t, file.UnlimitedDownloads, false)
	test.IsEqualBool(t, file.UnlimitedTime, false)

	dbInstance.DeleteMetaData("testfile")
	test.IsEqualInt(t, len(dbInstance.GetAllMetadata()), 0)

	dbInstance.SaveMetaData(models.File{
		Id:                 "test2",
		Name:               "test2",
		UnlimitedDownloads: true,
		UnlimitedTime:      false,
	})

	file, ok = dbInstance.GetMetaDataById("test2")
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, file.UnlimitedDownloads, true)
	test.IsEqualBool(t, file.UnlimitedTime, false)

	dbInstance.SaveMetaData(models.File{
		Id:                 "test3",
		Name:               "test3",
		DownloadsRemaining: 4,
		UnlimitedDownloads: false,
		UnlimitedTime:      true,
	})
	file, ok = dbInstance.GetMetaDataById("test3")
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, file.UnlimitedDownloads, false)
	test.IsEqualBool(t, file.UnlimitedTime, true)
	test.IsEqualInt(t, file.DownloadsRemaining, 4)
	test.IsEqualInt64(t, file.WindowOpenedAt, 0)
	dbInstance.Close()
	defer test.ExpectPanic(t)
	_ = dbInstance.GetAllMetadata()
}

func TestDatabaseProvider_GetType(t *testing.T) {
	test.IsEqualInt(t, dbInstance.GetType(), 0)
}

func TestHotlink(t *testing.T) {
	instance, err := New(config)
	test.IsNil(t, err)
	dbInstance = instance

	dbInstance.SaveHotlink(models.File{Id: "testfile", Name: "test.txt", HotlinkId: "testlink", ExpireAt: time.Now().Add(time.Hour).Unix()})

	hotlink, ok := dbInstance.GetHotlink("testlink")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, hotlink, "testfile")
	_, ok = dbInstance.GetHotlink("invalid")
	test.IsEqualBool(t, ok, false)

	dbInstance.DeleteHotlink("invalid")
	_, ok = dbInstance.GetHotlink("testlink")
	test.IsEqualBool(t, ok, true)
	dbInstance.DeleteHotlink("testlink")
	_, ok = dbInstance.GetHotlink("testlink")
	test.IsEqualBool(t, ok, false)

	dbInstance.SaveHotlink(models.File{Id: "testfile", Name: "test.txt", HotlinkId: "testlink", ExpireAt: 0, UnlimitedTime: true})
	hotlink, ok = dbInstance.GetHotlink("testlink")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, hotlink, "testfile")

	dbInstance.SaveHotlink(models.File{Id: "file2", Name: "file2.txt", HotlinkId: "link2", ExpireAt: time.Now().Add(time.Hour).Unix()})
	dbInstance.SaveHotlink(models.File{Id: "file3", Name: "file3.txt", HotlinkId: "link3", ExpireAt: time.Now().Add(time.Hour).Unix()})

	hotlinks := dbInstance.GetAllHotlinks()
	test.IsEqualInt(t, len(hotlinks), 3)
	test.IsEqualBool(t, slices.Contains(hotlinks, "testlink"), true)
	test.IsEqualBool(t, slices.Contains(hotlinks, "link2"), true)
	test.IsEqualBool(t, slices.Contains(hotlinks, "link3"), true)
	dbInstance.DeleteHotlink("")
	hotlinks = dbInstance.GetAllHotlinks()
	test.IsEqualInt(t, len(hotlinks), 3)
}

func TestDatabaseProvider_AcquireDownload(t *testing.T) {
	newFile := models.File{
		Id:                 "newFileId",
		Name:               "newFileName",
		Size:               "3GB",
		SHA1:               "newSHA1",
		PasswordHash:       "newPassword",
		HotlinkId:          "newHotlink",
		ContentType:        "newContent",
		AwsBucket:          "newAws",
		ExpireAt:           123456,
		SizeBytes:          456789,
		DownloadsRemaining: 11,
		DownloadCount:      2,
		Encryption: models.EncryptionInfo{
			IsEncrypted:         true,
			IsEndToEndEncrypted: true,
			DecryptionKey:       []byte("newDecryptionKey"),
			Nonce:               []byte("newDecryptionNonce"),
		},
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
	}
	dbInstance.SaveMetaData(newFile)
	dbInstance.IncreaseDownloadCount(newFile.Id)
	retrievedFile, ok := dbInstance.GetMetaDataById(newFile.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, retrievedFile.DownloadCount, 3)
	test.IsEqualInt(t, retrievedFile.DownloadsRemaining, 11)
	newFile.DownloadCount = 3
	// NameEncryptedRaw is populated only on a read (see models.File.NameEncryptedRaw), so the
	// freshly constructed newFile never carries it; cleared here so the comparison below is
	// about the fields this test actually cares about.
	retrievedFile.NameEncryptedRaw = nil
	test.IsEqual(t, retrievedFile, newFile)

	timeNow := time.Now().Unix()
	granted, opened := dbInstance.AcquireDownload(newFile.Id, timeNow, 0)
	test.IsEqualBool(t, granted, true)
	test.IsEqualBool(t, opened, true)
	retrievedFile, ok = dbInstance.GetMetaDataById(newFile.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, retrievedFile.DownloadCount, 4)
	test.IsEqualInt(t, retrievedFile.DownloadsRemaining, 10)
	newFile.DownloadCount = 4
	newFile.DownloadsRemaining = 10
	newFile.WindowOpenedAt = timeNow
	retrievedFile.NameEncryptedRaw = nil
	test.IsEqual(t, retrievedFile, newFile)
	dbInstance.DeleteMetaData(newFile.Id)
}

// TestAcquireDownloadConcurrentFirstRequests is the test for AcquireDownload's third step. Two
// requests arriving together on a one-pickup file both find no window open; one wins the
// conditional UPDATE and opens it, and the other's UPDATE matches nothing because the allowance
// is now spent. Without the re-check that follows, that loser is refused - which is exactly the
// "your download broke, and it cost you your only one" failure the window exists to remove, just
// moved to a race instead of a dropped connection. Both must be granted, exactly one must report
// having opened the window, and the allowance must land on 0 rather than going negative.
//
// Run over several iterations because the interleaving is not guaranteed on any single one.
func TestAcquireDownloadConcurrentFirstRequests(t *testing.T) {
	const iterations = 50
	const workers = 8
	const leeway = 3600

	for i := 0; i < iterations; i++ {
		id := "concurrentwindow" + strconv.Itoa(i)
		dbInstance.SaveMetaData(models.File{Id: id, Name: id, DownloadsRemaining: 1})
		timeNow := time.Now().Unix()

		var wg sync.WaitGroup
		var grantedCount, openedCount int32
		wg.Add(workers)
		for j := 0; j < workers; j++ {
			go func() {
				defer wg.Done()
				granted, opened := dbInstance.AcquireDownload(id, timeNow, leeway)
				if granted {
					atomic.AddInt32(&grantedCount, 1)
				}
				if opened {
					atomic.AddInt32(&openedCount, 1)
				}
			}()
		}
		wg.Wait()

		test.IsEqualInt(t, int(grantedCount), workers)
		test.IsEqualInt(t, int(openedCount), 1)
		stored, ok := dbInstance.GetMetaDataById(id)
		test.IsEqualBool(t, ok, true)
		test.IsEqualInt(t, stored.DownloadsRemaining, 0)
		test.IsEqualInt(t, stored.DownloadCount, 1)
		dbInstance.DeleteMetaData(id)
	}
}

func TestApiKey(t *testing.T) {
	key1 := models.ApiKey{
		Id:           "newkey",
		FriendlyName: "New Key",
		LastUsed:     100,
		Permissions:  20,
		PublicId:     "_n3wkey",
		Expiry:       0,
		IsSystemKey:  false,
		UserId:       5,
	}
	key2 := models.ApiKey{
		Id:           "newkey2",
		FriendlyName: "New Key2",
		PublicId:     "_n3wkey2",
		Expiry:       17362039396,
		LastUsed:     200,
		Permissions:  40,
		IsSystemKey:  true,
		UserId:       10,
	}
	dbInstance.SaveApiKey(key1)
	dbInstance.SaveApiKey(key2)
	dbInstance.SaveApiKey(models.ApiKey{
		Id:           "expiredKey",
		PublicId:     "expiredKey",
		FriendlyName: "expiredKey",
		Expiry:       1,
	})

	keys := dbInstance.GetAllApiKeys()
	test.IsEqualInt(t, len(keys), 2)
	test.IsEqual(t, keys["newkey"], key1)
	test.IsEqual(t, keys["newkey2"], key2)
	dbInstance.DeleteApiKey("newkey2")
	test.IsEqualInt(t, len(dbInstance.GetAllApiKeys()), 1)

	key, ok := dbInstance.GetApiKey("newkey")
	test.IsEqualBool(t, ok, true)
	test.IsEqual(t, key, key1)
	_, ok = dbInstance.GetApiKey("newkey2")
	test.IsEqualBool(t, ok, false)

	dbInstance.SaveApiKey(models.ApiKey{
		Id:           "newkey",
		FriendlyName: "Old Key",
		LastUsed:     100,
	})
	key, ok = dbInstance.GetApiKey("newkey")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, key.FriendlyName, "Old Key")
}

func TestSession(t *testing.T) {
	renewAt := time.Now().Add(1 * time.Hour).Unix()
	dbInstance.SaveSession("newsession", models.Session{
		RenewAt:    renewAt,
		ValidUntil: time.Now().Add(2 * time.Hour).Unix(),
	})

	session, ok := dbInstance.GetSession("newsession")
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, session.RenewAt == renewAt, true)

	dbInstance.DeleteSession("newsession")
	_, ok = dbInstance.GetSession("newsession")
	test.IsEqualBool(t, ok, false)

	dbInstance.SaveSession("newsession", models.Session{
		RenewAt:    renewAt,
		ValidUntil: time.Now().Add(2 * time.Hour).Unix(),
	})

	dbInstance.SaveSession("anothersession", models.Session{
		RenewAt:    renewAt,
		ValidUntil: time.Now().Add(2 * time.Hour).Unix(),
	})
	_, ok = dbInstance.GetSession("newsession")
	test.IsEqualBool(t, ok, true)
	_, ok = dbInstance.GetSession("anothersession")
	test.IsEqualBool(t, ok, true)

	dbInstance.DeleteAllSessions()
	_, ok = dbInstance.GetSession("newsession")
	test.IsEqualBool(t, ok, false)
	_, ok = dbInstance.GetSession("anothersession")
	test.IsEqualBool(t, ok, false)

	session = models.Session{
		RenewAt:    2147483645,
		ValidUntil: 2147483645,
		UserId:     20,
	}
	dbInstance.SaveSession("sess_user1", session)
	dbInstance.SaveSession("sess_user2", session)
	dbInstance.SaveSession("sess_user3", session)
	session.UserId = 40
	dbInstance.SaveSession("sess_user4", session)
	_, ok = dbInstance.GetSession("sess_user1")
	test.IsEqualBool(t, ok, true)
	_, ok = dbInstance.GetSession("sess_user2")
	test.IsEqualBool(t, ok, true)
	_, ok = dbInstance.GetSession("sess_user3")
	test.IsEqualBool(t, ok, true)
	_, ok = dbInstance.GetSession("sess_user4")
	test.IsEqualBool(t, ok, true)
	dbInstance.DeleteAllSessionsByUser(20)
	_, ok = dbInstance.GetSession("sess_user1")
	test.IsEqualBool(t, ok, false)
	_, ok = dbInstance.GetSession("sess_user2")
	test.IsEqualBool(t, ok, false)
	_, ok = dbInstance.GetSession("sess_user3")
	test.IsEqualBool(t, ok, false)
	_, ok = dbInstance.GetSession("sess_user4")
	test.IsEqualBool(t, ok, true)
}

func TestFileRequest(t *testing.T) {
	// Create first file request
	req1 := models.FileRequest{
		Id:           "req1",
		Name:         "New file request",
		UserId:       45564,
		ApiKey:       "123",
		CreationDate: time.Now().Unix(),
	}
	dbInstance.SaveFileRequest(req1)

	// Get existing file request
	request, ok := dbInstance.GetFileRequest("req1")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, request.Id, "req1")
	test.IsEqualString(t, request.Name, "New file request")

	test.IsEqualBool(t, request.Closed, false)

	// Closing and reopening has to survive a round trip, otherwise a request marked complete
	// starts accepting uploads again on the next read
	req1.Closed = true
	dbInstance.SaveFileRequest(req1)
	request, ok = dbInstance.GetFileRequest("req1")
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, request.Closed, true)
	req1.Closed = false
	dbInstance.SaveFileRequest(req1)
	request, _ = dbInstance.GetFileRequest("req1")
	test.IsEqualBool(t, request.Closed, false)

	// Get invalid file request
	_, ok = dbInstance.GetFileRequest("invalid")
	test.IsEqualBool(t, ok, false)

	// Empty ID should return false
	_, ok = dbInstance.GetFileRequest("")
	test.IsEqualBool(t, ok, false)

	// Delete invalid request (should not panic or affect data)
	dbInstance.DeleteFileRequest(models.FileRequest{Id: "invalid"})
	_, ok = dbInstance.GetFileRequest("req1")
	test.IsEqualBool(t, ok, true)

	// Delete valid request
	dbInstance.DeleteFileRequest(req1)
	_, ok = dbInstance.GetFileRequest("req1")
	test.IsEqualBool(t, ok, false)

	// Create multiple file requests to test GetAllFileRequests
	req2 := models.FileRequest{
		Id:           "req2",
		UserId:       45564,
		Name:         "file2.txt",
		ApiKey:       "456",
		CreationDate: time.Now().Add(-time.Minute).Unix(),
	}
	req3 := models.FileRequest{
		Id:           "req3",
		Name:         "file3.txt",
		UserId:       45564,
		ApiKey:       "789",
		CreationDate: time.Now().Add(-2 * time.Minute).Unix(),
	}

	dbInstance.SaveFileRequest(req1)
	dbInstance.SaveFileRequest(req2)
	dbInstance.SaveFileRequest(req3)

	requests := dbInstance.GetAllFileRequests()
	test.IsEqualInt(t, len(requests), 3)

	ids := []string{
		requests[0].Id,
		requests[1].Id,
		requests[2].Id,
	}

	test.IsEqualBool(t, slices.Contains(ids, "req1"), true)
	test.IsEqualBool(t, slices.Contains(ids, "req2"), true)
	test.IsEqualBool(t, slices.Contains(ids, "req3"), true)

	// Ensure sorting by CreationDate DESC
	test.IsEqualBool(t, requests[0].CreationDate >= requests[1].CreationDate, true)
	test.IsEqualBool(t, requests[1].CreationDate >= requests[2].CreationDate, true)

}

func TestFileRequestCollaborators(t *testing.T) {
	req := models.FileRequest{
		Id:           "reqCollab",
		Name:         "Collab request",
		UserId:       1,
		ApiKey:       "collabkey",
		CreationDate: time.Now().Unix(),
	}
	req.SetCollaboratorIds([]int{9, 4, 9})
	dbInstance.SaveFileRequest(req)

	stored, ok := dbInstance.GetFileRequest("reqCollab")
	test.IsEqualBool(t, ok, true)
	test.IsEqual(t, stored.CollaboratorIds(), []int{4, 9})
	test.IsEqualString(t, stored.CollaboratorsRaw, "[4,9]")
	test.IsEqualBool(t, stored.IsCollaborator(9), true)

	// Clearing has to survive the round trip too, or a removed collaborator keeps access.
	stored.SetCollaboratorIds(nil)
	dbInstance.SaveFileRequest(stored)
	stored, _ = dbInstance.GetFileRequest("reqCollab")
	test.IsEqualInt(t, len(stored.Collaborators), 0)
	test.IsEqualString(t, stored.CollaboratorsRaw, "[]")

	// A request saved without ever touching the list (every caller before this feature) reads
	// back as nobody, never as null.
	plain := models.FileRequest{Id: "reqPlain", Name: "Plain", UserId: 1, ApiKey: "plainkey", CreationDate: time.Now().Unix()}
	dbInstance.SaveFileRequest(plain)
	stored, _ = dbInstance.GetFileRequest("reqPlain")
	test.IsEqualBool(t, stored.Collaborators != nil, true)
	test.IsEqualInt(t, len(stored.Collaborators), 0)

	dbInstance.DeleteFileRequest(req)
	dbInstance.DeleteFileRequest(plain)
}

func TestGarbageCollectionSessions(t *testing.T) {
	dbInstance.SaveSession("todelete1", models.Session{
		RenewAt:    time.Now().Add(-10 * time.Second).Unix(),
		ValidUntil: time.Now().Add(-10 * time.Second).Unix(),
	})
	dbInstance.SaveSession("todelete2", models.Session{
		RenewAt:    time.Now().Add(10 * time.Second).Unix(),
		ValidUntil: time.Now().Add(-10 * time.Second).Unix(),
	})
	dbInstance.SaveSession("tokeep1", models.Session{
		RenewAt:    time.Now().Add(-10 * time.Second).Unix(),
		ValidUntil: time.Now().Add(10 * time.Second).Unix(),
	})
	dbInstance.SaveSession("tokeep2", models.Session{
		RenewAt:    time.Now().Add(10 * time.Second).Unix(),
		ValidUntil: time.Now().Add(10 * time.Second).Unix(),
	})
	for _, item := range []string{"todelete1", "todelete2", "tokeep1", "tokeep2"} {
		_, result := dbInstance.GetSession(item)
		test.IsEqualBool(t, result, true)
	}
	dbInstance.RunGarbageCollection()
	for _, item := range []string{"todelete1", "todelete2"} {
		_, result := dbInstance.GetSession(item)
		test.IsEqualBool(t, result, false)
	}
	for _, item := range []string{"tokeep1", "tokeep2"} {
		_, result := dbInstance.GetSession(item)
		test.IsEqualBool(t, result, true)
	}
}

func TestEnd2EndInfo(t *testing.T) {
	info := dbInstance.GetEnd2EndInfo(4)
	test.IsEqualInt(t, info.Version, 0)
	test.IsEqualBool(t, info.HasBeenSetUp(), false)

	dbInstance.SaveEnd2EndInfo(models.E2EInfoEncrypted{
		Version:        1,
		Nonce:          []byte("testNonce1"),
		Content:        []byte("testContent1"),
		AvailableFiles: nil,
	}, 4)

	info = dbInstance.GetEnd2EndInfo(4)
	test.IsEqualInt(t, info.Version, 1)
	test.IsEqualBool(t, info.HasBeenSetUp(), true)
	test.IsEqualByteSlice(t, info.Nonce, []byte("testNonce1"))
	test.IsEqualByteSlice(t, info.Content, []byte("testContent1"))
	test.IsEqualBool(t, len(info.AvailableFiles) == 0, true)

	dbInstance.SaveEnd2EndInfo(models.E2EInfoEncrypted{
		Version:        2,
		Nonce:          []byte("testNonce2"),
		Content:        []byte("testContent2"),
		AvailableFiles: nil,
	}, 4)

	info = dbInstance.GetEnd2EndInfo(4)
	test.IsEqualInt(t, info.Version, 2)
	test.IsEqualBool(t, info.HasBeenSetUp(), true)
	test.IsEqualByteSlice(t, info.Nonce, []byte("testNonce2"))
	test.IsEqualByteSlice(t, info.Content, []byte("testContent2"))
	test.IsEqualBool(t, len(info.AvailableFiles) == 0, true)

	dbInstance.DeleteEnd2EndInfo(4)
	info = dbInstance.GetEnd2EndInfo(4)
	test.IsEqualInt(t, info.Version, 0)
	test.IsEqualBool(t, info.HasBeenSetUp(), false)
}

func TestUpdateTimeApiKey(t *testing.T) {
	retrievedKey, ok := dbInstance.GetApiKey("key1")
	test.IsEqualBool(t, ok, false)
	test.IsEqualString(t, retrievedKey.Id, "")

	key := models.ApiKey{
		Id:           "key1",
		FriendlyName: "key1",
		PublicId:     "key1",
		LastUsed:     100,
	}
	dbInstance.SaveApiKey(key)
	key = models.ApiKey{
		Id:           "key2",
		FriendlyName: "key2",
		PublicId:     "key2",
		LastUsed:     200,
	}
	dbInstance.SaveApiKey(key)

	retrievedKey, ok = dbInstance.GetApiKey("key1")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, retrievedKey.Id, "key1")
	test.IsEqualInt64(t, retrievedKey.LastUsed, 100)
	retrievedKey, ok = dbInstance.GetApiKey("key2")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, retrievedKey.Id, "key2")
	test.IsEqualInt64(t, retrievedKey.LastUsed, 200)

	key.LastUsed = 300
	dbInstance.UpdateTimeApiKey(key)

	retrievedKey, ok = dbInstance.GetApiKey("key1")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, retrievedKey.Id, "key1")
	test.IsEqualInt64(t, retrievedKey.LastUsed, 100)
	retrievedKey, ok = dbInstance.GetApiKey("key2")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, retrievedKey.Id, "key2")
	test.IsEqualInt64(t, retrievedKey.LastUsed, 300)

	dbInstance.SaveApiKey(models.ApiKey{
		Id:       "publicTest",
		PublicId: "publicId",
	})
	_, ok = dbInstance.GetApiKey("publicTest")
	test.IsEqualBool(t, ok, true)
	_, ok = dbInstance.GetApiKey("publicId")
	test.IsEqualBool(t, ok, false)
	_, ok = dbInstance.GetApiKeyByPublicKey("publicTest")
	test.IsEqualBool(t, ok, false)
	keyName, ok := dbInstance.GetApiKeyByPublicKey("publicId")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, keyName, "publicTest")
}

func TestParallelConnectionsWritingAndReading(t *testing.T) {
	var wg sync.WaitGroup

	simulatedConnection := func(t *testing.T) {
		file := models.File{
			Id:                 helper.GenerateRandomString(10),
			Name:               helper.GenerateRandomString(10),
			Size:               "10B",
			SHA1:               "1289423794287598237489",
			ExpireAt:           math.MaxInt,
			SizeBytes:          10,
			DownloadsRemaining: 10,
			DownloadCount:      10,
			PasswordHash:       "",
			HotlinkId:          "",
			ContentType:        "",
			AwsBucket:          "",
			Encryption:         models.EncryptionInfo{},
			UnlimitedDownloads: false,
			UnlimitedTime:      false,
		}
		dbInstance.SaveMetaData(file)
		retrievedFile, ok := dbInstance.GetMetaDataById(file.Id)
		test.IsEqualBool(t, ok, true)
		test.IsEqualString(t, retrievedFile.Name, file.Name)
		dbInstance.DeleteMetaData(file.Id)
		_, ok = dbInstance.GetMetaDataById(file.Id)
		test.IsEqualBool(t, ok, false)
	}

	for i := 1; i <= 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			simulatedConnection(t)
		}()
	}
	wg.Wait()
}

func TestParallelConnectionsReading(t *testing.T) {
	var wg sync.WaitGroup

	dbInstance.SaveApiKey(models.ApiKey{
		Id:           "readtest",
		FriendlyName: "readtest",
		LastUsed:     40000,
	})
	simulatedConnection := func(t *testing.T) {
		_, ok := dbInstance.GetApiKey("readtest")
		test.IsEqualBool(t, ok, true)
	}

	for i := 1; i <= 1000; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			simulatedConnection(t)
		}()
	}
	wg.Wait()
}

func TestUsers(t *testing.T) {
	users := dbInstance.GetAllUsers()
	test.IsEqualInt(t, len(users), 0)
	user := models.User{
		Id:            2,
		Name:          "test",
		Permissions:   models.UserPermissionAll,
		UserLevel:     models.UserLevelUser,
		LastOnline:    1337,
		Password:      "123456",
		ResetPassword: true,
	}
	dbInstance.SaveUser(user, false)
	retrievedUser, ok := dbInstance.GetUser(2)
	test.IsEqualBool(t, ok, true)
	test.IsEqual(t, retrievedUser, user)
	users = dbInstance.GetAllUsers()
	test.IsEqualInt(t, len(users), 1)
	test.IsEqualInt(t, retrievedUser.Id, 2)

	_, ok = dbInstance.GetUser(0)
	test.IsEqualBool(t, ok, false)
	_, ok = dbInstance.GetUserByName("invalid")
	test.IsEqualBool(t, ok, false)
	retrievedUser, ok = dbInstance.GetUserByName("test")
	test.IsEqualBool(t, ok, true)
	test.IsEqual(t, retrievedUser, user)

	dbInstance.DeleteUser(2)
	_, ok = dbInstance.GetUser(2)
	test.IsEqualBool(t, ok, false)

	user = models.User{
		Id:            1000,
		Name:          "test2",
		Permissions:   models.UserPermissionNone,
		UserLevel:     models.UserLevelAdmin,
		LastOnline:    1338,
		Password:      "1234568",
		ResetPassword: true,
	}
	dbInstance.SaveUser(user, true)
	_, ok = dbInstance.GetUser(1000)
	test.IsEqualBool(t, ok, false)
	retrievedUser, ok = dbInstance.GetUserByName("test2")
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, retrievedUser.Id == 1000, false)
	user.Id = retrievedUser.Id
	test.IsEqual(t, retrievedUser, user)

	dbInstance.UpdateUserLastOnline(retrievedUser.Id)
	retrievedUser, ok = dbInstance.GetUser(retrievedUser.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, time.Now().Unix()-retrievedUser.LastOnline < 5, true)
	test.IsEqualBool(t, time.Now().Unix()-retrievedUser.LastOnline > -1, true)

	user.Name = "test1"
	dbInstance.SaveUser(user, true)
	user.Name = "test3"
	dbInstance.SaveUser(user, true)
	user.Name = "test99"
	user.UserLevel = models.UserLevelSuperAdmin
	dbInstance.SaveUser(user, true)
	user.Name = "test0"
	user.UserLevel = models.UserLevelUser
	dbInstance.SaveUser(user, true)

	users = dbInstance.GetAllUsers()
	test.IsEqualInt(t, len(users), 5)
	test.IsEqualString(t, users[0].Name, "test99")
	test.IsEqualString(t, users[1].Name, "test2")
	test.IsEqualString(t, users[2].Name, "test1")
	test.IsEqualString(t, users[3].Name, "test3")
	test.IsEqualString(t, users[4].Name, "test0")
}

func TestDatabaseProvider_Upgrade(t *testing.T) {
	instance, err := New(configUpgrade)
	test.IsNil(t, err)

	exitCode := 0
	osExit = func(code int) {
		exitCode = code
	}
	instance.SetDbVersion(9)
	instance.Upgrade(instance.GetDbVersion())
	test.IsEqualInt(t, exitCode, 1)

	// exitCode = 0
	// instance.SetDbVersion(6)
	// instance.Upgrade(instance.GetDbVersion())
	// test.IsEqualInt(t, exitCode, 0)

}

// TestDatabaseProvider_UpgradeV17Idempotent reproduces a crash between the two ALTER TABLE
// statements (or between them and the version bump, which only happens once the whole ladder in
// Upgrade has run): the next boot re-runs the v17 step against a Users table that already has
// one or both of the columns. Before the fix this panicked with "duplicate column name" - a
// bricked database on every subsequent boot, the same failure mode the earlier Postgres bug had.
// createNewDatabase already writes the current schema (including AuthProvider and OidcSubject),
// so calling Upgrade with a stale currentDbVersion of 16 against that schema reproduces exactly
// this: the columns already exist, but the version says the step has not run yet.
func TestDatabaseProvider_UpgradeV17Idempotent(t *testing.T) {
	instance, err := New(models.DbConnection{
		HostUrl: "./test/newfolder/gokapi_v17idempotent.sqlite",
		Type:    0, // dbabstraction.TypeSqlite
	})
	test.IsNil(t, err)
	defer instance.Close()

	test.IsEqualBool(t, instance.columnExists("Users", "AuthProvider"), true)
	test.IsEqualBool(t, instance.columnExists("Users", "OidcSubject"), true)
	test.IsEqualBool(t, instance.columnExists("Sessions", "IsOauth"), true)
	test.IsEqualBool(t, instance.columnExists("Users", "NonExistentColumn"), false)

	// Must not panic: this is the crash-recovery replay of the v17 and v18 steps.
	instance.Upgrade(16)

	// Re-running it again (a second replay) must also be safe.
	instance.Upgrade(16)
}

// TestDatabaseProvider_UpgradeV18WipesSessions verifies that a session created before the
// v18 IsOauth column existed has no valid value for it, and the column's DEFAULT (0/false) has no
// way to know whether that session was actually created by the OAuth callback. Without wiping
// sessions in the v18 step, such a session would silently renew as a password session from then
// on, skipping the OAuth recheck interval that is supposed to re-verify group membership on every
// renewal. The v18 step must call DeleteAllSessions so no session straddles the schema change.
func TestDatabaseProvider_UpgradeV18WipesSessions(t *testing.T) {
	instance, err := New(models.DbConnection{
		HostUrl: "./test/newfolder/gokapi_v18wipessessions.sqlite",
		Type:    0, // dbabstraction.TypeSqlite
	})
	test.IsNil(t, err)
	defer instance.Close()

	instance.SaveSession("presessionv18", models.Session{
		RenewAt:    time.Now().Add(1 * time.Hour).Unix(),
		ValidUntil: time.Now().Add(2 * time.Hour).Unix(),
		IsOauth:    true,
	})
	_, ok := instance.GetSession("presessionv18")
	test.IsEqualBool(t, ok, true)

	// Replay the v18 step against a database whose schema is already current (createNewDatabase
	// writes the current schema) but whose stored version claims v17 has not run yet - the same
	// crash-recovery shape as TestDatabaseProvider_UpgradeV17Idempotent above.
	instance.Upgrade(17)

	_, ok = instance.GetSession("presessionv18")
	test.IsEqualBool(t, ok, false)
}

// TestDatabaseProvider_UpgradeV29AddsBundleDeletedAt is the upgrade path an instance already
// running v28 takes. createNewDatabase writes the current schema, so the v28 shape is reproduced by
// dropping the column again from a bundle that was saved with it - which also proves the ladder
// runs against a table that really is missing the column, not one that merely claims to be. The
// existing row must come back with DeletedAt at 0: it was never deleted, because a deleted folder
// used to be removed outright.
func TestDatabaseProvider_UpgradeV29AddsBundleDeletedAt(t *testing.T) {
	instance, err := New(models.DbConnection{
		HostUrl: "./test/newfolder/gokapi_v29deletedat.sqlite",
		Type:    0, // dbabstraction.TypeSqlite
	})
	test.IsNil(t, err)
	defer instance.Close()

	instance.SaveFileBundle(models.FileBundle{
		Id:           "v29bundle",
		Name:         "v29bundle",
		UserId:       5,
		CreationDate: time.Now().Unix(),
	})
	test.IsNil(t, instance.rawSqlite(`ALTER TABLE FileBundles DROP COLUMN "DeletedAt"`))
	test.IsEqualBool(t, instance.columnExists("FileBundles", "DeletedAt"), false)

	instance.Upgrade(28)

	test.IsEqualBool(t, instance.columnExists("FileBundles", "DeletedAt"), true)
	bundle, ok := instance.GetFileBundle("v29bundle")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, bundle.Name, "v29bundle")
	test.IsEqualInt64(t, bundle.DeletedAt, 0)

	// Re-running the step, the crash-recovery replay the v17 step above documents, must also be
	// safe.
	instance.Upgrade(28)
	test.IsEqualBool(t, instance.columnExists("FileBundles", "DeletedAt"), true)
}

func TestRawSql(t *testing.T) {
	dbInstance.Close()
	dbInstance.sqliteDb = nil
	defer test.ExpectPanic(t)
	_ = dbInstance.rawSqlite("Select * from Sessions")
}

// TestFileNameNotStoredInPlaintext is the requirement this provider exists to satisfy: a file
// name must not be readable in the database itself. Asserted against the raw database file rather
// than through the provider, because reading it back through SaveMetaData/GetMetaDataById would
// pass just as happily with the name stored in the clear - the threat here is whoever holds a
// dump, a backup or a read grant, not the application.
func TestFileNameNotStoredInPlaintext(t *testing.T) {
	key, err := encryption.GetRandomCipher()
	test.IsNil(t, err)
	encryption.Init(models.Configuration{Encryption: models.Encryption{
		Level: encryption.FullEncryptionStored, Cipher: key}})
	defer encryption.Init(models.Configuration{Encryption: models.Encryption{Level: encryption.NoEncryption}})

	const secretName = "2026-layoffs-final-do-not-share.xlsx"
	instance, err := New(config)
	test.IsNil(t, err)
	instance.SaveMetaData(models.File{Id: "plaintextNameTest", Name: secretName, SHA1: "abc"})

	retrieved, ok := instance.GetMetaDataById("plaintextNameTest")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, retrieved.Name, secretName)
	instance.Close()

	rawDatabase, err := os.ReadFile(config.HostUrl)
	test.IsNil(t, err)
	test.IsEqualBool(t, bytes.Contains(rawDatabase, []byte(secretName)), false)
}

// TestMigratePlaintextFileNames covers the upgrade path for a database written before file names
// were encrypted: the name has to be moved into NameEncrypted and the plaintext column removed,
// leaving nothing behind for a later dump to pick up. Re-running it must be a no-op, because it
// is called on every unseal rather than once.
func TestMigratePlaintextFileNames(t *testing.T) {
	key, err := encryption.GetRandomCipher()
	test.IsNil(t, err)
	encryption.Init(models.Configuration{Encryption: models.Encryption{
		Level: encryption.FullEncryptionStored, Cipher: key}})
	defer encryption.Init(models.Configuration{Encryption: models.Encryption{Level: encryption.NoEncryption}})

	const legacyName = "pre-migration-invoice.pdf"
	instance, err := New(models.DbConnection{HostUrl: "./test/newfolder/gokapi_names.sqlite"})
	test.IsNil(t, err)
	defer instance.Close()

	// Recreate the pre-v22 shape: a plaintext Name column, populated, with NameEncrypted unset.
	test.IsNil(t, instance.rawSqlite(`ALTER TABLE FileMetaData ADD COLUMN "Name" TEXT NOT NULL DEFAULT ''`))
	instance.SaveMetaData(models.File{Id: "legacyNameTest", SHA1: "def"})
	_, err = instance.sqliteDb.Exec(`UPDATE FileMetaData SET Name = ?, NameEncrypted = NULL WHERE Id = ?`,
		legacyName, "legacyNameTest")
	test.IsNil(t, err)

	test.IsEqualInt(t, instance.MigratePlaintextFileNames(), 1)
	test.IsEqualBool(t, instance.columnExists("FileMetaData", "Name"), false)

	migrated, ok := instance.GetMetaDataById("legacyNameTest")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, migrated.Name, legacyName)

	test.IsEqualInt(t, instance.MigratePlaintextFileNames(), 0)
}

// TestFolderNameNotStoredInPlaintext mirrors TestFileNameNotStoredInPlaintext for FileBundles
// (folders): a folder name is auto-derived from a member filename ("server.pem +2 more"), so it
// leaks a filename directly if it is ever readable in the raw database file.
func TestFolderNameNotStoredInPlaintext(t *testing.T) {
	key, err := encryption.GetRandomCipher()
	test.IsNil(t, err)
	encryption.Init(models.Configuration{Encryption: models.Encryption{
		Level: encryption.FullEncryptionStored, Cipher: key}})
	defer encryption.Init(models.Configuration{Encryption: models.Encryption{Level: encryption.NoEncryption}})

	const secretName = "server.pem +2 more"
	dbPath := "./test/newfolder/gokapi_bundle_plaintext.sqlite"
	instance, err := New(models.DbConnection{HostUrl: dbPath})
	test.IsNil(t, err)
	instance.SaveFileBundle(models.FileBundle{Id: "plaintextBundleTest", Name: secretName, UserId: 1, CreationDate: time.Now().Unix()})

	retrieved, ok := instance.GetFileBundle("plaintextBundleTest")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, retrieved.Name, secretName)
	instance.Close()

	rawDatabase, err := os.ReadFile(dbPath)
	test.IsNil(t, err)
	test.IsEqualBool(t, bytes.Contains(rawDatabase, []byte(secretName)), false)
}

// TestRequestNameAndNoteNotStoredInPlaintext mirrors TestFileNameNotStoredInPlaintext for
// UploadRequests: both the request name and the free-text note the owner typed must not be
// readable in the raw database file.
func TestRequestNameAndNoteNotStoredInPlaintext(t *testing.T) {
	key, err := encryption.GetRandomCipher()
	test.IsNil(t, err)
	encryption.Init(models.Configuration{Encryption: models.Encryption{
		Level: encryption.FullEncryptionStored, Cipher: key}})
	defer encryption.Init(models.Configuration{Encryption: models.Encryption{Level: encryption.NoEncryption}})

	const secretName = "Board minutes upload"
	const secretNote = "Please redact page 4 before uploading, contains SSNs"
	dbPath := "./test/newfolder/gokapi_request_plaintext.sqlite"
	instance, err := New(models.DbConnection{HostUrl: dbPath})
	test.IsNil(t, err)
	instance.SaveFileRequest(models.FileRequest{Id: "plaintextRequestTest", Name: secretName, Notes: secretNote,
		UserId: 1, ApiKey: "plaintextRequestTestKey", CreationDate: time.Now().Unix()})

	retrieved, ok := instance.GetFileRequest("plaintextRequestTest")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, retrieved.Name, secretName)
	test.IsEqualString(t, retrieved.Notes, secretNote)
	instance.Close()

	rawDatabase, err := os.ReadFile(dbPath)
	test.IsNil(t, err)
	test.IsEqualBool(t, bytes.Contains(rawDatabase, []byte(secretName)), false)
	test.IsEqualBool(t, bytes.Contains(rawDatabase, []byte(secretNote)), false)
}

// TestMigratePlaintextBundleAndRequestNames covers the upgrade path for FileBundles and
// UploadRequests rows written before these columns were encrypted, mirroring
// TestMigratePlaintextFileNames. Name and note are migrated together in one
// MigratePlaintextFileNames call, which reports their combined count (see LogFileNameMigration).
// Re-running it must be a no-op, because it is called on every unseal rather than once.
func TestMigratePlaintextBundleAndRequestNames(t *testing.T) {
	key, err := encryption.GetRandomCipher()
	test.IsNil(t, err)
	encryption.Init(models.Configuration{Encryption: models.Encryption{
		Level: encryption.FullEncryptionStored, Cipher: key}})
	defer encryption.Init(models.Configuration{Encryption: models.Encryption{Level: encryption.NoEncryption}})

	const legacyBundleName = "pre-migration-folder"
	const legacyRequestName = "pre-migration-request"
	const legacyRequestNote = "pre-migration-note"

	instance, err := New(models.DbConnection{HostUrl: "./test/newfolder/gokapi_migrate_bundle_request.sqlite"})
	test.IsNil(t, err)
	defer instance.Close()

	// Recreate the pre-v23 shape: plaintext name/note columns, populated, with the *Encrypted
	// columns unset - the same shape TestMigratePlaintextFileNames recreates for FileMetaData.
	test.IsNil(t, instance.rawSqlite(`ALTER TABLE FileBundles ADD COLUMN "name" TEXT NOT NULL DEFAULT ''`))
	test.IsNil(t, instance.rawSqlite(`ALTER TABLE UploadRequests ADD COLUMN "name" TEXT NOT NULL DEFAULT ''`))
	test.IsNil(t, instance.rawSqlite(`ALTER TABLE UploadRequests ADD COLUMN "note" TEXT NOT NULL DEFAULT ''`))

	instance.SaveFileBundle(models.FileBundle{Id: "legacyBundle", UserId: 1, CreationDate: time.Now().Unix()})
	_, err = instance.sqliteDb.Exec(`UPDATE FileBundles SET name = ?, NameEncrypted = NULL WHERE id = ?`,
		legacyBundleName, "legacyBundle")
	test.IsNil(t, err)

	instance.SaveFileRequest(models.FileRequest{Id: "legacyRequest", UserId: 1, ApiKey: "legacyRequestKey", CreationDate: time.Now().Unix()})
	_, err = instance.sqliteDb.Exec(`UPDATE UploadRequests SET name = ?, note = ?, NameEncrypted = NULL, NoteEncrypted = NULL WHERE id = ?`,
		legacyRequestName, legacyRequestNote, "legacyRequest")
	test.IsNil(t, err)

	// One bundle name, one request name and one request note - three plaintext values in total.
	test.IsEqualInt(t, instance.MigratePlaintextFileNames(), 3)
	test.IsEqualBool(t, instance.columnExists("FileBundles", "name"), false)
	test.IsEqualBool(t, instance.columnExists("UploadRequests", "name"), false)
	test.IsEqualBool(t, instance.columnExists("UploadRequests", "note"), false)

	migratedBundle, ok := instance.GetFileBundle("legacyBundle")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, migratedBundle.Name, legacyBundleName)

	migratedRequest, ok := instance.GetFileRequest("legacyRequest")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, migratedRequest.Name, legacyRequestName)
	test.IsEqualString(t, migratedRequest.Notes, legacyRequestNote)

	test.IsEqualInt(t, instance.MigratePlaintextFileNames(), 0)
}

// TestBackfillBundleSettingsFromMembers covers the v27 migration step: existing bundles have no
// password/expiry/downloads of their own until this runs, and the values it backfills come from
// the bundle's CURRENT members - see models.DeriveBundleSettingsFromMembers for the merge rule.
// Three bundles: members that agree on every field (the simple case), members that disagree on
// every field (must land on the most restrictive value along each axis, not an arbitrary
// member's), and a bundle with no surviving members at all (stays at the zero-value defaults).
func TestBackfillBundleSettingsFromMembers(t *testing.T) {
	instance, err := New(models.DbConnection{HostUrl: "./test/newfolder/gokapi_bundle_backfill.sqlite"})
	test.IsNil(t, err)
	defer instance.Close()

	agreeBundle := models.FileBundle{Id: "agreeBundle", UserId: 1, CreationDate: time.Now().Unix()}
	instance.SaveFileBundle(agreeBundle)
	const sharedHash = "sharedhash123"
	instance.SaveMetaData(models.File{Id: "agreeMember1", BundleId: agreeBundle.Id, SHA1: "a",
		PasswordHash: sharedHash, ExpireAt: 1800000000, DownloadsRemaining: 4, UploadDate: 100})
	instance.SaveMetaData(models.File{Id: "agreeMember2", BundleId: agreeBundle.Id, SHA1: "a",
		PasswordHash: sharedHash, ExpireAt: 1800000000, DownloadsRemaining: 4, UploadDate: 200})

	disagreeBundle := models.FileBundle{Id: "disagreeBundle", UserId: 1, CreationDate: time.Now().Unix()}
	instance.SaveFileBundle(disagreeBundle)
	// Uploaded first, unprotected, the loosest expiry and the largest download cap.
	instance.SaveMetaData(models.File{Id: "disagreeEarlier", BundleId: disagreeBundle.Id, SHA1: "a",
		ExpireAt: 1900000000, DownloadsRemaining: 9, UploadDate: 50})
	// Uploaded second, but protected, with a tighter expiry and a smaller download cap.
	instance.SaveMetaData(models.File{Id: "disagreeLater", BundleId: disagreeBundle.Id, SHA1: "a",
		PasswordHash: "laterhash", ExpireAt: 1700000000, DownloadsRemaining: 2, UploadDate: 150})

	emptyBundle := models.FileBundle{Id: "emptyBundle", UserId: 1, CreationDate: time.Now().Unix()}
	instance.SaveFileBundle(emptyBundle)

	// Replay the v27 step against a database whose schema is already current (New() writes it,
	// including these columns at their zero default) but whose stored version claims v26 - the
	// same crash-recovery/fresh-backfill shape TestDatabaseProvider_UpgradeV18WipesSessions uses.
	instance.Upgrade(26)

	agreeStored, ok := instance.GetFileBundle(agreeBundle.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, agreeStored.PasswordHash, sharedHash)
	test.IsEqualInt64(t, agreeStored.ExpireAt, 1800000000)
	test.IsEqualBool(t, agreeStored.UnlimitedTime, false)
	test.IsEqualInt(t, agreeStored.DownloadsRemaining, 4)
	test.IsEqualBool(t, agreeStored.UnlimitedDownloads, false)

	disagreeStored, ok := instance.GetFileBundle(disagreeBundle.Id)
	test.IsEqualBool(t, ok, true)
	// Any member ever protected makes the bundle protected - unprotected would be strictly more
	// accessible than before. disagreeEarlier has no password, so the earliest PROTECTED member
	// (disagreeLater) is the one whose hash is used.
	test.IsEqualString(t, disagreeStored.PasswordHash, "laterhash")
	// Most restrictive (smallest) expiry wins, not the earliest-uploaded member's.
	test.IsEqualInt64(t, disagreeStored.ExpireAt, 1700000000)
	test.IsEqualBool(t, disagreeStored.UnlimitedTime, false)
	// Most restrictive (smallest) download cap wins.
	test.IsEqualInt(t, disagreeStored.DownloadsRemaining, 2)
	test.IsEqualBool(t, disagreeStored.UnlimitedDownloads, false)

	emptyStored, ok := instance.GetFileBundle(emptyBundle.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, emptyStored.PasswordHash, "")
	test.IsEqualInt64(t, emptyStored.ExpireAt, 0)
	test.IsEqualBool(t, emptyStored.UnlimitedTime, false)
	test.IsEqualInt(t, emptyStored.DownloadsRemaining, 0)
	test.IsEqualBool(t, emptyStored.UnlimitedDownloads, false)

	// Re-running the step (a crash-recovery replay) reproduces the same values rather than
	// drifting: it is a pure function of the members, which have not changed.
	instance.Upgrade(26)
	agreeStoredAgain, ok := instance.GetFileBundle(agreeBundle.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqual(t, agreeStoredAgain, agreeStored)
}

// TestClearingNoteActuallyClears guards the Note write path against the bug the "empty means
// sealed" heuristic (correct for Name, see encryptRequestNameForSave) would reintroduce if reused
// for Note: an empty note is a normal value an owner can set by clearing a note they previously
// typed, and must actually overwrite the stored ciphertext rather than being mistaken for "this
// FileRequest was read back while sealed, keep what's stored".
func TestClearingNoteActuallyClears(t *testing.T) {
	key, err := encryption.GetRandomCipher()
	test.IsNil(t, err)
	encryption.Init(models.Configuration{Encryption: models.Encryption{
		Level: encryption.FullEncryptionStored, Cipher: key}})
	defer encryption.Init(models.Configuration{Encryption: models.Encryption{Level: encryption.NoEncryption}})

	instance, err := New(models.DbConnection{HostUrl: "./test/newfolder/gokapi_clear_note.sqlite"})
	test.IsNil(t, err)
	defer instance.Close()

	request := models.FileRequest{Id: "noteClearTest", UserId: 1, ApiKey: "noteClearTestKey",
		CreationDate: time.Now().Unix(), Notes: "Please double-check the invoice total"}
	instance.SaveFileRequest(request)

	saved, ok := instance.GetFileRequest("noteClearTest")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, saved.Notes, "Please double-check the invoice total")

	// The owner clears the note. saved.NoteEncryptedRaw still carries the old encrypted bytes (see
	// models.FileRequest.NoteEncryptedRaw) - if encryptNoteForSave used the same heuristic as
	// encryptRequestNameForSave, it would write those old bytes back verbatim instead of an
	// encrypted empty string, and the note would silently fail to clear.
	saved.Notes = ""
	instance.SaveFileRequest(saved)

	cleared, ok := instance.GetFileRequest("noteClearTest")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, cleared.Notes, "")
}

// TestSealedReadRendersPlaceholder covers the read side of the same class of bug
// TestFileNameNotStoredInPlaintext's write side guards: a bundle or request name that cannot be
// decrypted (the instance is sealed) must render models.NameUnavailable rather than an empty
// string, and reading it must not panic. Notes has no placeholder convention - an empty note
// while sealed is indistinguishable from, and rendered the same as, a legitimately empty one.
func TestSealedReadRendersPlaceholder(t *testing.T) {
	key, err := encryption.GetRandomCipher()
	test.IsNil(t, err)
	encryption.Init(models.Configuration{Encryption: models.Encryption{
		Level: encryption.FullEncryptionStored, Cipher: key}})

	dbPath := "./test/newfolder/gokapi_sealed_read.sqlite"
	instance, err := New(models.DbConnection{HostUrl: dbPath})
	test.IsNil(t, err)
	defer instance.Close()

	instance.SaveFileBundle(models.FileBundle{Id: "sealedBundleTest", Name: "Quarterly reports",
		UserId: 1, CreationDate: time.Now().Unix()})
	instance.SaveFileRequest(models.FileRequest{Id: "sealedRequestTest", Name: "Vendor invoices", Notes: "please zip",
		UserId: 1, ApiKey: "sealedRequestTestKey", CreationDate: time.Now().Unix()})

	// Seal the instance: FullEncryptionInput, recorded but never unsealed.
	const checksumSalt = "sealed-read-test-checksum-salt"
	encryption.Init(models.Configuration{Encryption: models.Encryption{
		Level:        encryption.FullEncryptionInput,
		Salt:         "sealed-read-test-salt",
		ChecksumSalt: checksumSalt,
		Checksum:     encryption.PasswordChecksum("irrelevant-password", checksumSalt),
	}})
	defer encryption.Init(models.Configuration{Encryption: models.Encryption{Level: encryption.NoEncryption}})
	test.IsEqualBool(t, encryption.IsSealed(), true)

	bundle, ok := instance.GetFileBundle("sealedBundleTest")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, bundle.Name, "")
	test.IsEqualString(t, bundle.DisplayName(), models.NameUnavailable)

	request, ok := instance.GetFileRequest("sealedRequestTest")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, request.Name, "")
	test.IsEqualString(t, request.DisplayName(), models.NameUnavailable)
	test.IsEqualString(t, request.Notes, "")
}
