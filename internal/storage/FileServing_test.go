package storage

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/configuration/cloudconfig"
	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/encryption"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/storage/chunking"
	"github.com/forceu/gokapi/internal/storage/filesystem/s3filesystem/aws"
	"github.com/forceu/gokapi/internal/test"
	"github.com/forceu/gokapi/internal/test/testconfiguration"
	"github.com/forceu/gokapi/internal/webserver/downloadstatus"
)

func TestMain(m *testing.M) {
	testconfiguration.Create(true)
	configuration.Load()
	configuration.ConnectDatabase()
	var testserver *httptest.Server
	if testconfiguration.UseMockS3Server() {
		testserver = testconfiguration.StartS3TestServer()
	}
	exitVal := m.Run()
	testconfiguration.Delete()
	if testserver != nil {
		testserver.Close()
	}
	os.Exit(exitVal)
}

var idNewFile string

func TestGetFile(t *testing.T) {
	_, result := GetFile("invalid")
	test.IsEqualBool(t, result, false)

	file, result := GetFile("Wzol7LyY2QVczXynJtVo")
	fmt.Println(configuration.Get().DataDir)
	fmt.Println(configuration.Get().DatabaseUrl)
	test.IsEqualBool(t, result, true)
	test.IsEqualString(t, file.Id, "Wzol7LyY2QVczXynJtVo")
	test.IsEqualString(t, file.Name, "smallfile2")
	test.IsEqualString(t, file.Size, "8 B")
	test.IsEqualInt(t, file.DownloadsRemaining, 1)
	_, result = GetFile("deletedfile1234")
	test.IsEqualBool(t, result, false)
	_, result = GetFile("")
	test.IsEqualBool(t, result, false)
	file = models.File{
		Id:                 "testget",
		Name:               "testget",
		SHA1:               "testget",
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
	}
	database.SaveMetaData(file)
	_, result = GetFile(file.Id)
	test.IsEqualBool(t, result, false)

	// Test pending deletion - file should not be retrievable when pending deletion
	pendingFile := models.File{
		Id:                 "testpendingdelete",
		Name:               "testpendingdelete",
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		PendingDeletion:    time.Now().Add(time.Hour).Unix(),
	}
	database.SaveMetaData(pendingFile)
	_, result = GetFile(pendingFile.Id)
	test.IsEqualBool(t, result, false)
	// Clean up - cancel pending deletion to allow normal retrieval
	pendingFile.PendingDeletion = 0
	database.SaveMetaData(pendingFile)
	_, result = GetFile(pendingFile.Id)
	test.IsEqualBool(t, result, true)
	// Clean up test data
	database.DeleteMetaData(pendingFile.Id)
}

func TestGetFileByHotlink(t *testing.T) {
	_, result := GetFileByHotlink("invalid")
	test.IsEqualBool(t, result, false)
	_, result = GetFileByHotlink("")
	test.IsEqualBool(t, result, false)
	file, ok := GetFileByHotlink("PhSs6mFtf8O5YGlLMfNw9rYXx9XRNkzCnJZpQBi7inunv3Z4A.jpg")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, file.Id, "n1tSTAGj8zan9KaT4u6p")
	test.IsEqualString(t, file.Name, "picture.jpg")
	test.IsEqualString(t, file.Size, "4 B")
	test.IsEqualInt(t, file.DownloadsRemaining, 1)
}

func TestAddHotlink(t *testing.T) {
	file := models.File{Name: "test.dat", Id: "testId", ContentType: "image/jpg"}
	AddHotlink(&file)
	test.IsEqualString(t, file.HotlinkId, "")
	file = models.File{Name: "test.jpg", Id: "testId", ExpireAt: time.Now().Add(time.Hour).Unix(), ContentType: "image/jpg"}
	AddHotlink(&file)
	test.IsEqualInt(t, len(file.HotlinkId), 44)
	lastCharacters := file.HotlinkId[len(file.HotlinkId)-4:]
	test.IsEqualBool(t, lastCharacters == ".jpg", true)
	link, ok := database.GetHotlink(file.HotlinkId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, link, "testId")
	file = models.File{Name: "test.jpg", Id: "testId", ExpireAt: time.Now().Add(time.Hour).Unix(), ContentType: "image/jpg"}
	file.Encryption.IsEncrypted = true
	file.AwsBucket = "test"
	AddHotlink(&file)
	test.IsEqualString(t, file.HotlinkId, "")
}

func TestAddHotlinkDisabled(t *testing.T) {
	os.Unsetenv("GOKAPI_DISABLE_HOTLINKS")
	// Upstream behaviour: unset env var still allows hotlinking of an image file
	file := models.File{Name: "test.jpg", Id: "testId", ExpireAt: time.Now().Add(time.Hour).Unix(), ContentType: "image/jpg"}
	test.IsEqualBool(t, IsAbleHotlink(file), true)
	AddHotlink(&file)
	test.IsEqualBool(t, len(file.HotlinkId) > 0, true)

	os.Setenv("GOKAPI_DISABLE_HOTLINKS", "true")
	defer os.Unsetenv("GOKAPI_DISABLE_HOTLINKS")
	// Same, otherwise hotlinkable file is refused once hotlinks are disabled
	file = models.File{Name: "test.jpg", Id: "testId", ExpireAt: time.Now().Add(time.Hour).Unix(), ContentType: "image/jpg"}
	test.IsEqualBool(t, IsAbleHotlink(file), false)
	AddHotlink(&file)
	test.IsEqualString(t, file.HotlinkId, "")
}

func TestPurgeHotlinksIfDisabled(t *testing.T) {
	os.Unsetenv("GOKAPI_DISABLE_HOTLINKS")
	file := models.File{
		Id:                 "purgehotlinktest",
		Name:               "purgehotlinktest.jpg",
		SHA1:               "purgehotlinktest",
		ContentType:        "image/jpg",
		HotlinkId:          "purgehotlinktestlink.jpg",
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
	}
	database.SaveMetaData(file)
	database.SaveHotlink(file)
	_, ok := database.GetHotlink(file.HotlinkId)
	test.IsEqualBool(t, ok, true)

	// Upstream behaviour: with the env var unset, a pre-existing hotlink is left untouched
	purgeHotlinksIfDisabled()
	_, ok = database.GetHotlink(file.HotlinkId)
	test.IsEqualBool(t, ok, true)
	storedFile, ok := database.GetMetaDataById(file.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, storedFile.HotlinkId, file.HotlinkId)

	// Enabling the env var must purge the hotlink and clear it from the file, even though the
	// hotlink was created before the setting was switched on
	os.Setenv("GOKAPI_DISABLE_HOTLINKS", "true")
	defer os.Unsetenv("GOKAPI_DISABLE_HOTLINKS")
	purgeHotlinksIfDisabled()
	_, ok = database.GetHotlink(file.HotlinkId)
	test.IsEqualBool(t, ok, false)
	storedFile, ok = database.GetMetaDataById(file.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, storedFile.HotlinkId, "")
}

type testFile struct {
	File    models.File
	Request models.UploadParameters
	Header  multipart.FileHeader
	UserId  int
	Content []byte
}

func createRawTestFile(content []byte) (multipart.FileHeader, models.UploadParameters) {
	os.Setenv("TZ", "UTC")
	mimeHeader := make(textproto.MIMEHeader)
	mimeHeader.Set("Content-Disposition", "form-data; name=\"file\"; filename=\"test.dat\"")
	mimeHeader.Set("Content-Type", "text/plain")
	header := multipart.FileHeader{
		Filename: "test.dat",
		Header:   mimeHeader,
		Size:     int64(len(content)),
	}
	request := models.UploadParameters{
		AllowedDownloads: 1,
		Expiry:           999,
		ExpiryTimestamp:  2147483600,
		MaxMemory:        10,
	}
	return header, request
}

func createTestFile() (testFile, error) {
	content := []byte("This is a file for testing purposes")
	header, request := createRawTestFile(content)
	file, err := NewFile(bytes.NewReader(content), &header, 63, request)
	return testFile{
		File:    file,
		Request: request,
		Header:  header,
		Content: content,
		UserId:  63,
	}, err
}

func createTestChunk() (string, chunking.FileHeader, models.UploadParameters, error) {
	content := []byte("This is a file for chunk testing purposes")
	header, request := createRawTestFile(content)
	chunkId := helper.GenerateRandomString(15)
	fileheader := chunking.FileHeader{
		Filename:    header.Filename,
		ContentType: header.Header.Get("Content-Type"),
		Size:        header.Size,
	}
	err := os.WriteFile("test/data/chunk-"+chunkId, content, 0600)
	if err != nil {
		return "", chunking.FileHeader{}, models.UploadParameters{}, err
	}
	return chunkId, fileheader, request, nil
}

func TestNewFile(t *testing.T) {
	newFile, err := createTestFile()
	file := newFile.File
	request := newFile.Request
	content := newFile.Content
	header := newFile.Header

	test.IsNil(t, err)
	retrievedFile, ok := database.GetMetaDataById(file.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, retrievedFile.Name, "test.dat")
	test.IsEqualString(t, retrievedFile.SHA1, "f1474c19eff0fc8998fa6e1b1f7bf31793b103a6")
	test.IsEqualString(t, retrievedFile.HotlinkId, "")
	test.IsEqualString(t, retrievedFile.PasswordHash, "")
	test.IsEqualString(t, retrievedFile.Size, "35 B")
	test.IsEqualInt(t, retrievedFile.DownloadsRemaining, 1)
	test.IsEqualInt(t, len(retrievedFile.Id), 15)
	test.IsEqualInt(t, int(retrievedFile.ExpireAt), 2147483600)
	test.IsEqualBool(t, file.UnlimitedTime, false)
	test.IsEqualBool(t, file.UnlimitedDownloads, false)
	idNewFile = file.Id

	request.UnlimitedDownload = true
	file, err = NewFile(bytes.NewReader(content), &header, 99, request)
	test.IsNil(t, err)
	test.IsEqualInt(t, file.UserId, 99)
	test.IsEqualBool(t, file.UnlimitedTime, false)
	test.IsEqualBool(t, file.UnlimitedDownloads, true)
	request.UnlimitedDownload = false
	request.UnlimitedTime = true
	file, err = NewFile(bytes.NewReader(content), &header, 99, request)
	test.IsNil(t, err)
	test.IsEqualBool(t, file.UnlimitedTime, true)
	test.IsEqualBool(t, file.UnlimitedDownloads, false)
	request.UnlimitedDownload = true
	file, err = NewFile(bytes.NewReader(content), &header, 99, request)
	test.IsNil(t, err)
	test.IsEqualBool(t, file.UnlimitedTime, true)
	test.IsEqualBool(t, file.UnlimitedDownloads, true)

	withinLastSecond := file.UploadDate >= time.Now().Add(-1*time.Second).Unix() && file.UploadDate <= time.Now().Unix()
	test.IsEqualBool(t, withinLastSecond, true)

	createBigFile("bigfile", 20)
	bigFile, _ := os.Open("bigfile")
	mimeHeader := make(textproto.MIMEHeader)
	mimeHeader.Set("Content-Disposition", "form-data; name=\"file\"; filename=\"bigfile\"")
	mimeHeader.Set("Content-Type", "application/binary")
	header = multipart.FileHeader{
		Filename: "bigfile",
		Header:   mimeHeader,
		Size:     int64(20) * 1024 * 1024,
	}
	request = models.UploadParameters{
		AllowedDownloads: 1,
		Expiry:           999,
		ExpiryTimestamp:  2147483600,
		MaxMemory:        10,
	}
	// Also testing renaming of temp file
	file, err = NewFile(bigFile, &header, 99, request)
	test.IsNil(t, err)
	retrievedFile, ok = database.GetMetaDataById(file.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, retrievedFile.Name, "bigfile")
	test.IsEqualString(t, retrievedFile.SHA1, "9674344c90c2f0646f0b78026e127c9b86e3ad77")
	test.IsEqualString(t, retrievedFile.Size, "20.0 MB")
	_, err = bigFile.Seek(0, io.SeekStart)
	test.IsNil(t, err)
	// Testing removal of temp file
	test.IsEqualString(t, retrievedFile.Name, "bigfile")
	test.IsEqualString(t, retrievedFile.SHA1, "9674344c90c2f0646f0b78026e127c9b86e3ad77")
	test.IsEqualString(t, retrievedFile.Size, "20.0 MB")
	bigFile.Close()
	os.Remove("bigfile")

	createBigFile("bigfile", 50)
	bigFile, _ = os.Open("bigfile")
	mimeHeader = make(textproto.MIMEHeader)
	mimeHeader.Set("Content-Disposition", "form-data; name=\"file\"; filename=\"bigfile\"")
	mimeHeader.Set("Content-Type", "application/binary")
	header = multipart.FileHeader{
		Filename: "bigfile",
		Header:   mimeHeader,
		Size:     int64(50) * 1024 * 1024,
	}
	request = models.UploadParameters{
		AllowedDownloads: 1,
		Expiry:           999,
		ExpiryTimestamp:  2147483600,
		MaxMemory:        10,
	}
	file, err = NewFile(bigFile, &header, 99, request)
	test.IsNotNil(t, err)
	retrievedFile, ok = database.GetMetaDataById(file.Id)
	test.IsEqualBool(t, ok, false)
	bigFile.Close()
	os.Remove("bigfile")

	configuration.Get().Encryption.Level = 1
	cipher, err := encryption.GetRandomCipher()
	test.IsNil(t, err)
	encryption.Init(models.Configuration{Encryption: models.Encryption{
		Level:  encryption.LocalEncryptionStored,
		Cipher: cipher,
	}})

	// Encrypted uploads must never be deduplicated: two uploads of identical content (both the
	// in-memory and the temp-file path) get their own random storage identifier, their own blob
	// on disk and their own key/nonce, instead of sharing the first upload's.
	newFile, err = createTestFile()
	test.IsNil(t, err)
	retrievedFile, ok = database.GetMetaDataById(newFile.File.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, strings.HasPrefix(retrievedFile.SHA1, "enc-"), true)
	test.IsEqualBool(t, retrievedFile.Encryption.IsEncrypted, true)

	secondSmallFile, err := createTestFile()
	test.IsNil(t, err)
	secondSmallRetrieved, ok := database.GetMetaDataById(secondSmallFile.File.Id)
	test.IsEqualBool(t, ok, true)
	test.IsNotEqualString(t, retrievedFile.SHA1, secondSmallRetrieved.SHA1)
	test.IsEqualBool(t, bytes.Equal(retrievedFile.Encryption.DecryptionKey, secondSmallRetrieved.Encryption.DecryptionKey), false)
	test.FileExists(t, configuration.Get().DataDir+"/"+retrievedFile.SHA1)
	test.FileExists(t, configuration.Get().DataDir+"/"+secondSmallRetrieved.SHA1)

	createBigFile("bigfile", 20)
	header.Size = int64(20) * 1024 * 1024
	bigFile, _ = os.Open("bigfile")
	file, err = NewFile(bigFile, &header, 99, request)
	test.IsNil(t, err)
	retrievedFile, ok = database.GetMetaDataById(file.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, retrievedFile.Name, "bigfile")
	test.IsEqualBool(t, strings.HasPrefix(retrievedFile.SHA1, "enc-"), true)
	bigFile.Close()

	bigFile, _ = os.Open("bigfile")
	secondBigFile, err := NewFile(bigFile, &header, 99, request)
	test.IsNil(t, err)
	test.IsNotEqualString(t, retrievedFile.SHA1, secondBigFile.SHA1)
	test.IsEqualBool(t, bytes.Equal(retrievedFile.Encryption.DecryptionKey, secondBigFile.Encryption.DecryptionKey), false)
	test.FileExists(t, configuration.Get().DataDir+"/"+retrievedFile.SHA1)
	test.FileExists(t, configuration.Get().DataDir+"/"+secondBigFile.SHA1)
	bigFile.Close()
	os.Remove("bigfile")

	configuration.Get().Encryption.Level = 0

	if aws.IsIncludedInBuild {
		header = multipart.FileHeader{
			Filename: "bigfile",
			Header:   mimeHeader,
			Size:     int64(20) * 1024 * 1024,
		}
		request = models.UploadParameters{
			AllowedDownloads: 1,
			Expiry:           999,
			ExpiryTimestamp:  2147483600,
			MaxMemory:        10,
		}
		testconfiguration.EnableS3()
		config, ok := cloudconfig.Load()
		test.IsEqualBool(t, ok, true)
		ok = aws.Init(config.Aws)
		test.IsEqualBool(t, ok, true)
		file, err = NewFile(bytes.NewReader(content), &header, 99, request)
		test.IsNil(t, err)
		retrievedFile, ok = database.GetMetaDataById(file.Id)
		test.IsEqualBool(t, ok, true)
		test.IsEqualString(t, retrievedFile.Name, "bigfile")
		test.IsEqualString(t, retrievedFile.SHA1, "f1474c19eff0fc8998fa6e1b1f7bf31793b103a6")
		test.IsEqualString(t, retrievedFile.Size, "20.0 MB")
		testconfiguration.DisableS3()
	}
}

func TestNewFileFromChunk(t *testing.T) {
	test.FileDoesNotExist(t, "test/data/6cca7a6905774e6d61a77dca3ad7a1f44581d6ab")
	id, header, request, err := createTestChunk()
	test.IsNil(t, err)
	file, err := NewFileFromChunk(id, header, 99, request)
	test.IsNil(t, err)
	test.IsEqualString(t, file.Name, "test.dat")
	test.IsEqualString(t, file.Size, "41 B")
	test.IsEqualString(t, file.SHA1, "6cca7a6905774e6d61a77dca3ad7a1f44581d6ab")
	test.IsEqualInt64(t, file.ExpireAt, 2147483600)
	test.IsEqualInt(t, file.DownloadsRemaining, 1)
	test.IsEqualInt(t, file.DownloadCount, 0)
	test.IsEmpty(t, file.PasswordHash)
	test.IsEmpty(t, file.HotlinkId)
	test.IsEqualString(t, file.ContentType, "text/plain")
	test.IsEqualBool(t, file.UnlimitedTime, false)
	test.IsEqualBool(t, file.UnlimitedDownloads, false)
	test.FileExists(t, "test/data/6cca7a6905774e6d61a77dca3ad7a1f44581d6ab")
	test.FileDoesNotExist(t, "test/data/chunk-"+id)
	retrievedFile, ok := database.GetMetaDataById(file.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqual(t, file, retrievedFile)

	id, header, request, err = createTestChunk()
	header.Filename = "newfile"
	request.UnlimitedTime = true
	request.UnlimitedDownload = true
	test.IsNil(t, err)
	file, err = NewFileFromChunk(id, header, 99, request)
	test.IsNil(t, err)
	test.IsEqualString(t, file.Name, "newfile")
	test.IsEqualString(t, file.Size, "41 B")
	test.IsEqualString(t, file.SHA1, "6cca7a6905774e6d61a77dca3ad7a1f44581d6ab")
	test.IsEqualInt64(t, file.ExpireAt, 2147483600)
	test.IsEqualInt(t, file.DownloadsRemaining, 1)
	test.IsEqualInt(t, file.DownloadCount, 0)
	test.IsEmpty(t, file.PasswordHash)
	test.IsEmpty(t, file.HotlinkId)
	test.IsEqualString(t, file.ContentType, "text/plain")
	test.IsEqualBool(t, file.UnlimitedTime, true)
	test.IsEqualBool(t, file.UnlimitedDownloads, true)
	test.FileExists(t, "test/data/6cca7a6905774e6d61a77dca3ad7a1f44581d6ab")
	test.FileDoesNotExist(t, "test/data/chunk-"+id)
	retrievedFile, ok = database.GetMetaDataById(file.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqual(t, file, retrievedFile)
	withinLastSecond := file.UploadDate >= time.Now().Add(-1*time.Second).Unix() && file.UploadDate <= time.Now().Unix()
	test.IsEqualBool(t, withinLastSecond, true)
	err = os.Remove("test/data/6cca7a6905774e6d61a77dca3ad7a1f44581d6ab")
	test.IsNil(t, err)

	_, err = NewFileFromChunk("invalid", header, 99, request)
	test.IsNotNil(t, err)
	id, header, request, err = createTestChunk()
	test.IsNil(t, err)
	header.Size = 100000
	file, err = NewFileFromChunk(id, header, 99, request)
	test.IsNotNil(t, err)

	_, err = NewFileFromChunk("", header, 99, request)
	test.IsNotNil(t, err)

	if aws.IsIncludedInBuild {
		testconfiguration.EnableS3()
		config, ok := cloudconfig.Load()
		test.IsEqualBool(t, ok, true)
		ok = aws.Init(config.Aws)
		test.IsEqualBool(t, ok, true)
		id, header, request, err = createTestChunk()
		test.IsNil(t, err)
		file, err = NewFileFromChunk(id, header, 99, request)
		test.IsNil(t, err)
		test.IsEqualBool(t, file.AwsBucket != "", true)
		test.IsEqualString(t, file.SHA1, "6cca7a6905774e6d61a77dca3ad7a1f44581d6ab")
		retrievedFile, ok = database.GetMetaDataById(file.Id)
		test.IsEqual(t, file, retrievedFile)
		test.IsEqualBool(t, ok, true)
		testconfiguration.DisableS3()
	}
}

// TestNewFileFromChunkConcurrentCompletionIsIdempotent is the failing-first regression test for
// H3: before NewFileFromChunk serialised on chunkId (see its doc comment), N goroutines racing to
// complete the exact same chunk id each passed chunking.GetFileByChunkId successfully and each ran
// a full, redundant hash-and-encrypt pass before racing to remove the one shared source file - the
// losers of that race leaked their fully-encrypted tempFileEnc copy (see encryptChunkFile) until
// the periodic sweep, and an anonymous caller could multiply that cost at will simply by firing
// the same completion request N times in parallel. After the fix, exactly one call may succeed;
// every other call must fail cleanly (the chunk source file it needed was already consumed by the
// winner), and - crucially - no "upload*" encrypted temp file may be left behind in the data
// directory once every goroutine has returned.
func TestNewFileFromChunkConcurrentCompletionIsIdempotent(t *testing.T) {
	configuration.Get().Encryption.Level = 1
	cipher, err := encryption.GetRandomCipher()
	test.IsNil(t, err)
	encryption.Init(models.Configuration{Encryption: models.Encryption{
		Level:  encryption.LocalEncryptionStored,
		Cipher: cipher,
	}})
	defer func() { configuration.Get().Encryption.Level = 0 }()

	chunkId, fileHeader, request, err := createTestChunk()
	test.IsNil(t, err)

	const workers = 32
	var wg sync.WaitGroup
	wg.Add(workers)
	var ready sync.WaitGroup
	ready.Add(workers)
	start := make(chan struct{})
	var successes int32
	var successMu sync.Mutex
	var successFile models.File
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			// Every goroutine waits behind the same closed-channel gate so all workers enter
			// NewFileFromChunk as close to simultaneously as the scheduler allows - a plain
			// unsynchronised launch loop lets goroutines start staggered enough that the race
			// this test targets rarely, if ever, actually interleaves.
			ready.Done()
			<-start
			f, err := NewFileFromChunk(chunkId, fileHeader, 99, request)
			if err == nil {
				atomic.AddInt32(&successes, 1)
				successMu.Lock()
				successFile = f
				successMu.Unlock()
			}
		}()
	}
	ready.Wait()
	close(start)
	wg.Wait()

	test.IsEqualInt(t, int(successes), 1)

	_, ok := database.GetMetaDataById(successFile.Id)
	test.IsEqualBool(t, ok, true)

	// No orphaned "upload*" temp file (encryptChunkFile's tempFileEnc) may remain in the data
	// directory - a leaked one is exactly the disk-exhaustion vector H3 describes.
	entries, err := os.ReadDir(configuration.Get().DataDir)
	test.IsNil(t, err)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "upload") {
			t.Fatalf("orphaned encrypted temp file left behind: %s", e.Name())
		}
	}
}

// TestNewFileFromChunkDedupReusesKeyAndCiphertext locks the invariant on the
// production dedup path: when a chunk hashes to a file that already exists,
// copyEncryptionInfo must copy the existing key/nonce and leave the
// existing ciphertext blob untouched, never re-encrypt the new upload's
// content under that old key.
// TestNewFileFromChunkDedupAtNoEncryption covers the one path where
// deduplication still happens. Encrypted uploads now get a random,
// content-independent identifier so they are never deduplicated, which
// leaves NoEncryption as the only level where two identical uploads share
// a blob. Nothing else asserts that this still works, so a change that
// disabled dedup everywhere would otherwise pass unnoticed.
func TestNewFileFromChunkDedupAtNoEncryption(t *testing.T) {
	configuration.Get().Encryption.Level = encryption.NoEncryption
	previousSalt := configuration.Get().Authentication.SaltFiles
	configuration.Get().Authentication.SaltFiles = "testsaltdedup"
	defer func() {
		configuration.Get().Authentication.SaltFiles = previousSalt
		configuration.Get().Encryption.Level = 0
	}()

	content := []byte("This content is identical across both uploads, to exercise dedup")
	header, request := createRawTestFile(content)
	fileHeader := chunking.FileHeader{
		Filename:    header.Filename,
		ContentType: header.Header.Get("Content-Type"),
		Size:        header.Size,
	}

	chunkId1 := helper.GenerateRandomString(15)
	err := os.WriteFile("test/data/chunk-"+chunkId1, content, 0600)
	test.IsNil(t, err)
	file1, err := NewFileFromChunk(chunkId1, fileHeader, 99, request)
	test.IsNil(t, err)
	test.IsEqualBool(t, file1.Encryption.IsEncrypted, false)

	blobPath := configuration.Get().DataDir + "/" + file1.SHA1
	contentAfterFirst, err := os.ReadFile(blobPath)
	test.IsNil(t, err)

	chunkId2 := helper.GenerateRandomString(15)
	err = os.WriteFile("test/data/chunk-"+chunkId2, content, 0600)
	test.IsNil(t, err)
	file2, err := NewFileFromChunk(chunkId2, fileHeader, 99, request)
	test.IsNil(t, err)

	// Identical unencrypted content shares one blob
	test.IsEqualString(t, file1.SHA1, file2.SHA1)
	contentAfterSecond, err := os.ReadFile(blobPath)
	test.IsNil(t, err)
	test.IsEqualByteSlice(t, contentAfterFirst, contentAfterSecond)

	err = os.Remove(blobPath)
	test.IsNil(t, err)
}

// TestNewFileFromChunkDistinctContentGetsDistinctKeys locks the invariant
// that actually matters: two uploads that are NOT deduplicated - because
// their content differs - must never end up sharing key material, and each
// new stored blob is always encrypted under a freshly generated key. Unlike
// TestNewFileFromChunkDedupAtNoEncryption (which covers the remaining
// dedup path, where nothing is encrypted), this is the case that must
// never regress: a key covering two different plaintexts would be
// catastrophic AES-GCM nonce reuse.
func TestNewFileFromChunkDistinctContentGetsDistinctKeys(t *testing.T) {
	configuration.Get().Encryption.Level = encryption.LocalEncryptionStored
	previousSalt := configuration.Get().Authentication.SaltFiles
	configuration.Get().Authentication.SaltFiles = "testsaltdistinct"
	cipher, err := encryption.GetRandomCipher()
	test.IsNil(t, err)
	encryption.Init(models.Configuration{Encryption: models.Encryption{
		Level:  encryption.LocalEncryptionStored,
		Cipher: cipher,
	}})
	defer func() {
		configuration.Get().Authentication.SaltFiles = previousSalt
		configuration.Get().Encryption.Level = 0
	}()

	content1 := []byte("first upload's content, distinct from the second")
	content2 := []byte("second upload's content, distinct from the first")

	header1, request1 := createRawTestFile(content1)
	fileHeader1 := chunking.FileHeader{
		Filename:    header1.Filename,
		ContentType: header1.Header.Get("Content-Type"),
		Size:        header1.Size,
	}
	chunkId1 := helper.GenerateRandomString(15)
	err = os.WriteFile("test/data/chunk-"+chunkId1, content1, 0600)
	test.IsNil(t, err)
	file1, err := NewFileFromChunk(chunkId1, fileHeader1, 99, request1)
	test.IsNil(t, err)
	test.IsEqualBool(t, file1.Encryption.IsEncrypted, true)

	header2, request2 := createRawTestFile(content2)
	fileHeader2 := chunking.FileHeader{
		Filename:    header2.Filename,
		ContentType: header2.Header.Get("Content-Type"),
		Size:        header2.Size,
	}
	chunkId2 := helper.GenerateRandomString(15)
	err = os.WriteFile("test/data/chunk-"+chunkId2, content2, 0600)
	test.IsNil(t, err)
	file2, err := NewFileFromChunk(chunkId2, fileHeader2, 99, request2)
	test.IsNil(t, err)
	test.IsEqualBool(t, file2.Encryption.IsEncrypted, true)

	test.IsEqualBool(t, file1.SHA1 == file2.SHA1, false)
	test.IsEqualBool(t, bytes.Equal(file1.Encryption.DecryptionKey, file2.Encryption.DecryptionKey), false)
	test.IsEqualBool(t, bytes.Equal(file1.Encryption.Nonce, file2.Encryption.Nonce), false)

	// DecryptionKey holds the file key wrapped under the master cipher with a
	// per-file nonce, so comparing it alone would pass even if the same raw key
	// had been reused and merely rewrapped. Unwrap both and compare the actual
	// keys, which is the value that must never cover two distinct plaintexts.
	key1, err := encryption.GetCipherFromFile(file1.Encryption)
	test.IsNil(t, err)
	key2, err := encryption.GetCipherFromFile(file2.Encryption)
	test.IsNil(t, err)
	test.IsEqualBool(t, len(key1) > 0, true)
	test.IsEqualBool(t, bytes.Equal(key1, key2), false)

	err = os.Remove(configuration.Get().DataDir + "/" + file1.SHA1)
	test.IsNil(t, err)
	err = os.Remove(configuration.Get().DataDir + "/" + file2.SHA1)
	test.IsNil(t, err)
}

func TestDuplicateFile(t *testing.T) {

	tempFile, err := createTestFile()
	file := tempFile.File
	test.IsNil(t, err)
	retrievedFile, ok := database.GetMetaDataById(file.Id)
	test.IsEqualBool(t, ok, true)
	retrievedFile.DownloadCount = 5
	database.SaveMetaData(retrievedFile)

	newFile, err := DuplicateFile(retrievedFile, 0, "123", models.UploadParameters{})
	test.IsNil(t, err)
	test.IsEqualInt(t, newFile.DownloadCount, 0)
	test.IsEqualInt(t, newFile.DownloadsRemaining, 1)
	test.IsEqualInt64(t, newFile.ExpireAt, 2147483600)
	test.IsEqualString(t, newFile.PasswordHash, "")
	test.IsEqualBool(t, newFile.UnlimitedDownloads, false)
	test.IsEqualBool(t, newFile.UnlimitedTime, false)
	test.IsEqualString(t, newFile.Name, "test.dat")

	uploadRequest := models.UploadParameters{
		AllowedDownloads:  5,
		Expiry:            5,
		ExpiryTimestamp:   200000,
		Password:          "password1",
		UnlimitedDownload: true,
		UnlimitedTime:     true,
	}

	newFile, err = DuplicateFile(retrievedFile, 0, "123", uploadRequest)
	test.IsNil(t, err)
	test.IsEqualInt(t, newFile.DownloadCount, 0)
	test.IsEqualInt(t, newFile.DownloadsRemaining, 1)
	test.IsEqualInt64(t, newFile.ExpireAt, 2147483600)
	test.IsEqualString(t, newFile.PasswordHash, "")
	test.IsEqualBool(t, newFile.UnlimitedDownloads, false)
	test.IsEqualBool(t, newFile.UnlimitedTime, false)
	test.IsEqualString(t, newFile.Name, "test.dat")

	newFile, err = DuplicateFile(retrievedFile, ParamName, "123", uploadRequest)
	test.IsNil(t, err)
	test.IsEqualInt(t, newFile.DownloadCount, 0)
	test.IsEqualInt(t, newFile.DownloadsRemaining, 1)
	test.IsEqualInt64(t, newFile.ExpireAt, 2147483600)
	test.IsEqualString(t, newFile.PasswordHash, "")
	test.IsEqualBool(t, newFile.UnlimitedDownloads, false)
	test.IsEqualBool(t, newFile.UnlimitedTime, false)
	test.IsEqualString(t, newFile.Name, "123")

	newFile, err = DuplicateFile(retrievedFile, ParamExpiry, "123", uploadRequest)
	test.IsNil(t, err)
	test.IsEqualInt(t, newFile.DownloadCount, 0)
	test.IsEqualInt(t, newFile.DownloadsRemaining, 1)
	test.IsEqualInt64(t, newFile.ExpireAt, 200000)
	test.IsEqualString(t, newFile.PasswordHash, "")
	test.IsEqualBool(t, newFile.UnlimitedDownloads, false)
	test.IsEqualBool(t, newFile.UnlimitedTime, true)
	test.IsEqualString(t, newFile.Name, "test.dat")

	newFile, err = DuplicateFile(retrievedFile, ParamDownloads, "123", uploadRequest)
	test.IsNil(t, err)
	test.IsEqualInt(t, newFile.DownloadCount, 0)
	test.IsEqualInt(t, newFile.DownloadsRemaining, 5)
	test.IsEqualInt64(t, newFile.ExpireAt, 2147483600)
	test.IsEqualString(t, newFile.PasswordHash, "")
	test.IsEqualBool(t, newFile.UnlimitedDownloads, true)
	test.IsEqualBool(t, newFile.UnlimitedTime, false)
	test.IsEqualString(t, newFile.Name, "test.dat")

	newFile, err = DuplicateFile(retrievedFile, ParamPassword, "123", uploadRequest)
	test.IsNil(t, err)
	test.IsEqualInt(t, newFile.DownloadCount, 0)
	test.IsEqualInt(t, newFile.DownloadsRemaining, 1)
	test.IsEqualInt64(t, newFile.ExpireAt, 2147483600)
	test.IsNotEqualString(t, newFile.PasswordHash, "")
	test.IsEqualBool(t, newFile.UnlimitedDownloads, false)
	test.IsEqualBool(t, newFile.UnlimitedTime, false)
	test.IsEqualString(t, newFile.Name, "test.dat")

	retrievedFile.PasswordHash = "ahash"
	newFile, err = DuplicateFile(retrievedFile, 0, "123", uploadRequest)
	test.IsNil(t, err)
	test.IsEqualInt(t, newFile.DownloadCount, 0)
	test.IsEqualInt(t, newFile.DownloadsRemaining, 1)
	test.IsEqualInt64(t, newFile.ExpireAt, 2147483600)
	test.IsEqualString(t, newFile.PasswordHash, "ahash")
	test.IsEqualBool(t, newFile.UnlimitedDownloads, false)
	test.IsEqualBool(t, newFile.UnlimitedTime, false)
	test.IsEqualString(t, newFile.Name, "test.dat")

	// A duplicate request that explicitly asks to change the password (ParamPassword set,
	// which storage.DuplicateFile's caller only does when a password header was actually
	// present - see paramFilesDuplicate.ProcessParameter) but supplies an empty value must
	// be rejected, not silently produce an unprotected duplicate. This is the duplicate
	// path's equivalent of the whitespace-only-password confidentiality bug on the edit
	// path: the caller intended to set a password (isPresent=true), so an empty result -
	// whether truly empty or whitespace that trimmed away to nothing - is refused rather
	// than treated as "no password wanted".
	uploadRequest.Password = ""
	newFile, err = DuplicateFile(retrievedFile, ParamPassword, "123", uploadRequest)
	test.IsNotNil(t, err)
	test.IsEqualBool(t, errors.Is(err, configuration.ErrSharePasswordTooShort), true)

	uploadRequest.Password = "password2"
	newFile, err = DuplicateFile(retrievedFile, ParamExpiry|ParamPassword|ParamDownloads|ParamName, "123", uploadRequest)
	test.IsNil(t, err)
	test.IsEqualInt(t, newFile.DownloadCount, 0)
	test.IsEqualInt(t, newFile.DownloadsRemaining, 5)
	test.IsEqualInt64(t, newFile.ExpireAt, 200000)
	test.IsNotEqualString(t, newFile.PasswordHash, "")
	test.IsEqualBool(t, newFile.UnlimitedDownloads, true)
	test.IsEqualBool(t, newFile.UnlimitedTime, true)
	test.IsEqualString(t, newFile.Name, "123")

}

// TestDuplicateFileRejectsWhitespaceOnlyPassword proves the fix directly against a
// whitespace-only password, the exact string the reported bug used to reproduce a
// silently-unprotected file.
func TestDuplicateFileRejectsWhitespaceOnlyPassword(t *testing.T) {
	tempFile, err := createTestFile()
	test.IsNil(t, err)
	file := tempFile.File
	file.PasswordHash = "existinghash"
	database.SaveMetaData(file)

	_, err = DuplicateFile(file, ParamPassword, "duplicate.dat", models.UploadParameters{Password: "   "})
	test.IsNotNil(t, err)
	test.IsEqualBool(t, errors.Is(err, configuration.ErrSharePasswordTooShort), true)
}

func TestServeFile(t *testing.T) {
	file, result := GetFile(idNewFile)
	test.IsEqualBool(t, result, true)
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	ServeFile(file, w, r, true, true, false, false)
	_, result = GetFile(idNewFile)
	test.IsEqualBool(t, result, false)

	test.IsEqualString(t, w.Result().Header.Get("Content-Disposition"), "attachment; filename=\"test.dat\"; filename*=UTF-8''test.dat")
	test.IsEqualString(t, w.Result().Header.Get("Content-Length"), "35")
	test.IsEqualString(t, w.Result().Header.Get("Content-Type"), "text/plain")
	content, err := io.ReadAll(w.Result().Body)
	test.IsNil(t, err)
	test.IsEqualString(t, string(content), "This is a file for testing purposes")

	if aws.IsIncludedInBuild {
		testconfiguration.EnableS3()
		config, ok := cloudconfig.Load()
		test.IsEqualBool(t, ok, true)
		ok = aws.Init(config.Aws)
		test.IsEqualBool(t, ok, true)
		r = httptest.NewRequest("GET", "/", nil)
		w = httptest.NewRecorder()
		file, result = GetFile("awsTest1234567890123")
		test.IsEqualBool(t, result, true)
		ServeFile(file, w, r, false, true, false, false)
		if aws.IsMockApi {
			test.ResponseBodyContains(t, w, "https://redirect.url")
		} else {
			test.ResponseBodyContains(t, w, "<a href=\"http")
		}
		testconfiguration.DisableS3()
	}
	newFile, err := createTestFile()
	test.IsNil(t, err)
	file = newFile.File
	database.SaveMetaData(file)
	cipher, err := encryption.GetRandomCipher()
	test.IsNil(t, err)
	nonce, err := encryption.GetRandomNonce()
	test.IsNil(t, err)
	encryption.Init(models.Configuration{Encryption: models.Encryption{
		Level:  encryption.LocalEncryptionStored,
		Cipher: cipher,
	}})
	file.Encryption.IsEncrypted = true
	file.Encryption.DecryptionKey = cipher
	file.Encryption.Nonce = nonce
	r = httptest.NewRequest("GET", "/", nil)
	w = httptest.NewRecorder()
	ServeFile(file, w, r, true, true, false, false)
	test.ResponseBodyContains(t, w, "Error decrypting file")
}

// TestServeFileDeniedWhenExhaustedWithoutRecheck simulates the TOCTOU window the atomic decrement
// closes: the caller fetched the file while a download was still available (a stale
// file.DownloadsRemaining == 1 struct), but by the time ServeFile actually runs, a concurrent request
// has already consumed the last one and the database is authoritative at 0. This is exactly the shape
// of the API and presigned-download call sites (Api.go apiDownloadSingle, Webserver.go
// downloadPresigned), which call ServeFile with recheckExpiry == false and therefore never re-fetch
// DownloadsRemaining before deciding whether to serve - they must rely on IncreaseDownloadCount's own
// return value instead.
func TestServeFileDeniedWhenExhaustedWithoutRecheck(t *testing.T) {
	file := models.File{
		Id:                 "exhaustedNoRecheck",
		Name:               "exhaustedNoRecheck.txt",
		SHA1:               "exhaustedNoRecheck",
		ContentType:        "text/plain",
		DownloadsRemaining: 0,
		UnlimitedDownloads: false,
		UnlimitedTime:      true,
		SizeBytes:          4,
	}
	database.SaveMetaData(file)

	staleFile := file
	staleFile.DownloadsRemaining = 1

	r := httptest.NewRequest("GET", "/"+file.Id, nil)
	w := httptest.NewRecorder()
	served := ServeFile(staleFile, w, r, false, true, false, false)
	test.IsEqualBool(t, served, false)
	test.IsEqualInt(t, w.Body.Len(), 0)
	test.IsEqualInt(t, database.GetDownloadsRemaining(file.Id), 0)
}

// TestServeFileAuditWriteFailureRefusesDownload verifies the W7 fail-closed design: if the
// durable local audit record for a download cannot be written, the file must not be served.
func TestServeFileAuditWriteFailureRefusesDownload(t *testing.T) {
	auditPath := "test/data/audit.jsonl"
	test.IsNil(t, os.RemoveAll(auditPath))
	// os.OpenFile() on a directory fails with EISDIR regardless of user/permissions, which
	// gives a reliable, portable way to force the audit write to fail.
	test.IsNil(t, os.MkdirAll(auditPath, 0777))
	defer os.RemoveAll(auditPath)

	file := models.File{
		Id:                 "auditFailureTestFile",
		Name:               "should-not-be-served.txt",
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
	}
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handled := ServeFile(file, w, r, false, false, false, false)

	test.IsEqualBool(t, handled, true)
	test.IsEqualInt(t, w.Code, http.StatusServiceUnavailable)
	test.IsEqualBool(t, strings.Contains(w.Body.String(), file.Name), false)
}

func TestCleanUp(t *testing.T) {
	files := database.GetAllMetadata()
	downloadstatus.DeleteAll()
	downloadstatus.SetDownload(files["cleanuptest123456789"])

	test.IsEqualString(t, files["cleanuptest123456789"].Name, "cleanup")
	test.IsEqualString(t, files["Wzol7LyY2QVczXynJtVo"].Name, "smallfile2")
	test.IsEqualString(t, files["e4TjE7CokWK0giiLNxDL"].Name, "smallfile2")
	test.IsEqualString(t, files["wefffewhtrhhtrhtrhtr"].Name, "smallfile3")
	test.IsEqualString(t, files["n1tSTAGj8zan9KaT4u6p"].Name, "picture.jpg")
	test.IsEqualString(t, files["deletedfile123456789"].Name, "DeletedFile")
	test.IsEqualString(t, files["unlimitedDownload"].Name, "unlimitedDownload")
	test.IsEqualString(t, files["unlimitedTime"].Name, "unlimitedTime")
	test.FileExists(t, "test/data/2341354656543213246465465465432456898794")

	CleanUp(false)
	files = database.GetAllMetadata()
	test.IsEqualString(t, files["cleanuptest123456789"].Name, "cleanup")
	test.FileExists(t, "test/data/2341354656543213246465465465432456898794")
	test.IsEqualString(t, files["deletedfile123456789"].Name, "")
	test.IsEqualString(t, files["Wzol7LyY2QVczXynJtVo"].Name, "smallfile2")
	test.IsEqualString(t, files["e4TjE7CokWK0giiLNxDL"].Name, "smallfile2")
	test.IsEqualString(t, files["wefffewhtrhhtrhtrhtr"].Name, "smallfile3")
	test.IsEqualString(t, files["unlimitedDownload"].Name, "unlimitedDownload")
	test.IsEqualString(t, files["unlimitedTime"].Name, "unlimitedTime")
	test.IsEqualString(t, files["n1tSTAGj8zan9KaT4u6p"].Name, "picture.jpg")

	file, _ := GetFile("n1tSTAGj8zan9KaT4u6p")
	file.DownloadsRemaining = 0
	database.SaveMetaData(file)

	CleanUp(false)
	files = database.GetAllMetadata()
	test.FileDoesNotExist(t, "test/data/a8fdc205a9f19cc1c7507a60c4f01b13d11d7fd0")
	test.IsEqualString(t, files["n1tSTAGj8zan9KaT4u6p"].Name, "")
	test.IsEqualString(t, files["deletedfile123456789"].Name, "")
	test.IsEqualString(t, files["Wzol7LyY2QVczXynJtVo"].Name, "smallfile2")
	test.IsEqualString(t, files["e4TjE7CokWK0giiLNxDL"].Name, "smallfile2")
	test.IsEqualString(t, files["wefffewhtrhhtrhtrhtr"].Name, "smallfile3")

	file, _ = GetFile("Wzol7LyY2QVczXynJtVo")
	file.DownloadsRemaining = 0
	database.SaveMetaData(file)

	CleanUp(false)
	files = database.GetAllMetadata()
	test.FileExists(t, "test/data/e017693e4a04a59d0b0f400fe98177fe7ee13cf7")
	test.IsEqualString(t, files["Wzol7LyY2QVczXynJtVo"].Name, "")
	test.IsEqualString(t, files["n1tSTAGj8zan9KaT4u6p"].Name, "")
	test.IsEqualString(t, files["deletedfile123456789"].Name, "")
	test.IsEqualString(t, files["e4TjE7CokWK0giiLNxDL"].Name, "smallfile2")
	test.IsEqualString(t, files["wefffewhtrhhtrhtrhtr"].Name, "smallfile3")

	file, _ = GetFile("e4TjE7CokWK0giiLNxDL")
	file.DownloadsRemaining = 0
	database.SaveMetaData(file)
	file, _ = GetFile("wefffewhtrhhtrhtrhtr")
	file.DownloadsRemaining = 0
	database.SaveMetaData(file)

	CleanUp(false)
	files = database.GetAllMetadata()
	test.FileDoesNotExist(t, "test/data/e017693e4a04a59d0b0f400fe98177fe7ee13cf7")
	test.IsEqualString(t, files["Wzol7LyY2QVczXynJtVo"].Name, "")
	test.IsEqualString(t, files["n1tSTAGj8zan9KaT4u6p"].Name, "")
	test.IsEqualString(t, files["deletedfile123456789"].Name, "")
	test.IsEqualString(t, files["e4TjE7CokWK0giiLNxDL"].Name, "")
	test.IsEqualString(t, files["wefffewhtrhhtrhtrhtr"].Name, "")

	test.IsEqualString(t, files["cleanuptest123456789"].Name, "cleanup")
	test.FileExists(t, "test/data/2341354656543213246465465465432456898794")

	downloadstatus.DeleteAll()
	CleanUp(false)
	files = database.GetAllMetadata()
	test.IsEqualString(t, files["cleanuptest123456789"].Name, "")
	test.FileDoesNotExist(t, "test/data/2341354656543213246465465465432456898794")

	if aws.IsIncludedInBuild {
		testconfiguration.EnableS3()
		config, ok := cloudconfig.Load()
		test.IsEqualBool(t, ok, true)
		ok = aws.Init(config.Aws)
		test.IsEqualBool(t, ok, true)
		test.IsEqualString(t, files["awsTest1234567890123"].Name, "Aws Test File")
		testconfiguration.DisableS3()
	}
	// Doesn't really test anything
	CleanUp(true)
}

func TestDeleteFile(t *testing.T) {
	testconfiguration.Create(true)
	configuration.Load()
	configuration.ConnectDatabase()
	files := database.GetAllMetadata()
	test.IsEqualString(t, files["n1tSTAGj8zan9KaT4u6p"].Name, "picture.jpg")
	test.FileExists(t, "test/data/a8fdc205a9f19cc1c7507a60c4f01b13d11d7fd0")
	result := DeleteFile("n1tSTAGj8zan9KaT4u6p", true)
	time.Sleep(time.Second)
	test.IsEqualBool(t, result, true)
	files = database.GetAllMetadata()
	test.IsEqualString(t, files["n1tSTAGj8zan9KaT4u6p"].Name, "")
	test.FileDoesNotExist(t, "test/data/a8fdc205a9f19cc1c7507a60c4f01b13d11d7fd0")
	result = DeleteFile("invalid", true)
	time.Sleep(time.Second)
	test.IsEqualBool(t, result, false)
	result = DeleteFile("", true)
	time.Sleep(time.Second)
	test.IsEqualBool(t, result, false)

	testfile := models.File{Id: "testfiledownload", DownloadsRemaining: 1, ExpireAt: 2147483646}
	database.SaveMetaData(testfile)
	downloadstatus.SetDownload(testfile)
	file, ok := database.GetMetaDataById("testfiledownload")
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, file.ExpireAt != 0, true)
	DeleteFile(file.Id, false)
	file, ok = database.GetMetaDataById("testfiledownload")
	test.IsEqualInt(t, int(file.ExpireAt), 0)
	test.IsEqualBool(t, ok, true)

	if aws.IsIncludedInBuild {
		testconfiguration.EnableS3()
		config, ok := cloudconfig.Load()
		test.IsEqualBool(t, ok, true)
		ok = aws.Init(config.Aws)
		test.IsEqualBool(t, ok, true)
		awsFile := models.File{
			Id:        "awsTest1234567890123",
			Name:      "aws Test File",
			Size:      "20 MB",
			SHA1:      "x341354656543213246465465465432456898794",
			AwsBucket: "gokapi-test",
		}
		database.SaveMetaData(awsFile)
		files = database.GetAllMetadata()
		result, _, err := aws.FileExists(files["awsTest1234567890123"])
		test.IsEqualBool(t, result, true)
		test.IsNil(t, err)
		DeleteFile("awsTest1234567890123", true)
		time.Sleep(5 * time.Second)
		result, size, err := aws.FileExists(awsFile)
		test.IsEqualBool(t, result, false)
		test.IsEqualInt(t, int(size), 0)
		test.IsNil(t, err)
		testconfiguration.DisableS3()
	}
}

func createBigFile(name string, megabytes int64) {
	size := megabytes * 1024 * 1024
	file, _ := os.Create(name)
	_, _ = file.Seek(size-1, 0)
	_, _ = file.Write([]byte{0})
	_ = file.Close()
}

// TestNewFileFromChunkEncryptedNeverDeduplicated locks in that chunked uploads follow the same rule
// as NewFile: once server-side encryption is active, two chunk uploads with identical content must
// never share a blob or a key, must both remain independently downloadable, and deleting one must
// not affect the other. This runs after TestDeleteFile (which re-seeds the fixtures via
// testconfiguration.Create) because DeleteFile triggers an asynchronous, database-wide CleanUp that
// would otherwise race with the fixtures TestCleanUp depends on.
func TestNewFileFromChunkEncryptedNeverDeduplicated(t *testing.T) {
	configuration.Get().Encryption.Level = 1
	cipher, err := encryption.GetRandomCipher()
	test.IsNil(t, err)
	encryption.Init(models.Configuration{Encryption: models.Encryption{
		Level:  encryption.LocalEncryptionStored,
		Cipher: cipher,
	}})
	defer func() { configuration.Get().Encryption.Level = 0 }()

	content := []byte("identical chunk content uploaded twice while encryption is active")
	writeChunk := func() (string, chunking.FileHeader, models.UploadParameters) {
		header, request := createRawTestFile(content)
		chunkId := helper.GenerateRandomString(15)
		fileheader := chunking.FileHeader{
			Filename:    header.Filename,
			ContentType: header.Header.Get("Content-Type"),
			Size:        header.Size,
		}
		writeErr := os.WriteFile("test/data/chunk-"+chunkId, content, 0600)
		test.IsNil(t, writeErr)
		return chunkId, fileheader, request
	}

	chunkIdA, fileHeaderA, requestA := writeChunk()
	fileA, err := NewFileFromChunk(chunkIdA, fileHeaderA, 99, requestA)
	test.IsNil(t, err)

	chunkIdB, fileHeaderB, requestB := writeChunk()
	fileB, err := NewFileFromChunk(chunkIdB, fileHeaderB, 99, requestB)
	test.IsNil(t, err)

	test.IsEqualBool(t, strings.HasPrefix(fileA.SHA1, "enc-"), true)
	test.IsEqualBool(t, strings.HasPrefix(fileB.SHA1, "enc-"), true)
	test.IsNotEqualString(t, fileA.SHA1, fileB.SHA1)
	test.IsEqualBool(t, bytes.Equal(fileA.Encryption.DecryptionKey, fileB.Encryption.DecryptionKey), false)
	test.FileExists(t, configuration.Get().DataDir+"/"+fileA.SHA1)
	test.FileExists(t, configuration.Get().DataDir+"/"+fileB.SHA1)

	// Both must be independently downloadable and decrypt back to the original content.
	for _, f := range []models.File{fileA, fileB} {
		retrieved, ok := database.GetMetaDataById(f.Id)
		test.IsEqualBool(t, ok, true)
		r := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()
		served := ServeFile(retrieved, w, r, true, false, false, false)
		test.IsEqualBool(t, served, true)
		body, readErr := io.ReadAll(w.Result().Body)
		test.IsNil(t, readErr)
		test.IsEqualString(t, string(body), string(content))
	}

	// Deleting one file must not remove the other's independent blob.
	DeleteFile(fileA.Id, true)
	time.Sleep(time.Second)
	test.FileDoesNotExist(t, configuration.Get().DataDir+"/"+fileA.SHA1)
	test.FileExists(t, configuration.Get().DataDir+"/"+fileB.SHA1)
	_, ok := GetFile(fileB.Id)
	test.IsEqualBool(t, ok, true)

	DeleteFile(fileB.Id, true)
	time.Sleep(time.Second)
	test.FileDoesNotExist(t, configuration.Get().DataDir+"/"+fileB.SHA1)
}

// TestDuplicateFileSharesBlobEvenWhenEncrypted documents the deliberate exception to "never reuse a
// blob": DuplicateFile intentionally keeps sharing the source file's storage identifier and, if
// encrypted, its key and nonce, because the duplicate is byte-identical by construction (see the
// doc comment on DuplicateFile) rather than independently-uploaded content that merely happens to
// hash the same. CleanUp must not delete that shared blob while either metadata row still exists.
func TestDuplicateFileSharesBlobEvenWhenEncrypted(t *testing.T) {
	configuration.Get().Encryption.Level = 1
	cipher, err := encryption.GetRandomCipher()
	test.IsNil(t, err)
	encryption.Init(models.Configuration{Encryption: models.Encryption{
		Level:  encryption.LocalEncryptionStored,
		Cipher: cipher,
	}})
	defer func() { configuration.Get().Encryption.Level = 0 }()

	original, err := createTestFile()
	test.IsNil(t, err)
	originalFile := original.File

	duplicate, err := DuplicateFile(originalFile, 0, "", models.UploadParameters{})
	test.IsNil(t, err)

	test.IsEqualString(t, duplicate.SHA1, originalFile.SHA1)
	test.IsEqualByteSlice(t, duplicate.Encryption.DecryptionKey, originalFile.Encryption.DecryptionKey)
	test.IsEqualByteSlice(t, duplicate.Encryption.Nonce, originalFile.Encryption.Nonce)

	// Deleting the original must not remove the blob the duplicate still relies on.
	DeleteFile(originalFile.Id, true)
	time.Sleep(time.Second)
	test.FileExists(t, configuration.Get().DataDir+"/"+originalFile.SHA1)
	_, ok := GetFile(duplicate.Id)
	test.IsEqualBool(t, ok, true)

	// Deleting the duplicate as well must finally remove the now-unreferenced blob.
	DeleteFile(duplicate.Id, true)
	time.Sleep(time.Second)
	test.FileDoesNotExist(t, configuration.Get().DataDir+"/"+originalFile.SHA1)
}

func TestDeleteAllEncrypted(t *testing.T) {
	file := models.File{
		Id:            "testEncDelEnc",
		UnlimitedTime: true,
		Encryption: models.EncryptionInfo{
			IsEncrypted: true,
		},
	}
	database.SaveMetaData(file)
	file = models.File{
		Id:            "testEncDelUn",
		UnlimitedTime: true,
		Encryption: models.EncryptionInfo{
			IsEncrypted: false,
		},
	}
	database.SaveMetaData(file)
	data, ok := database.GetMetaDataById("testEncDelEnc")
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, data.UnlimitedTime, true)
	data, ok = database.GetMetaDataById("testEncDelUn")
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, data.UnlimitedTime, true)
}

func TestReplaceFile(t *testing.T) {
	originalFile := models.File{
		Id:                 "originalfiletest",
		Name:               "old.txt",
		Size:               "1KB",
		SHA1:               "replacetest1",
		ContentType:        "text/plain",
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		AwsBucket:          "",
		SizeBytes:          1024,
		Encryption: models.EncryptionInfo{
			IsEncrypted:         false,
			IsEndToEndEncrypted: false,
			DecryptionKey:       nil,
			Nonce:               nil,
		},
	}

	newFile := models.File{
		Id:                 "newfiletest",
		Name:               "new.txt",
		Size:               "2KB",
		SHA1:               "replacetest2",
		ContentType:        "text/plain2",
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		AwsBucket:          "",
		SizeBytes:          2048,
		Encryption: models.EncryptionInfo{
			IsEncrypted:         true,
			IsEndToEndEncrypted: false,
			DecryptionKey:       []byte("key"),
			Nonce:               []byte("nonce"),
		},
	}

	e2eFile := models.File{
		Id:                 "e2eFile",
		Name:               "e2eFile",
		Size:               "1KB",
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		SHA1:               "replacetest3",
		Encryption: models.EncryptionInfo{
			IsEncrypted:         true,
			IsEndToEndEncrypted: true,
		},
	}
	database.SaveMetaData(originalFile)
	_, ok := database.GetMetaDataById(originalFile.Id)
	test.IsEqualBool(t, ok, true)
	_, ok = GetFile(originalFile.Id)
	test.IsEqualBool(t, ok, true)
	database.SaveMetaData(newFile)
	_, ok = database.GetMetaDataById(newFile.Id)
	test.IsEqualBool(t, ok, true)
	database.SaveMetaData(e2eFile)
	_, ok = database.GetMetaDataById(e2eFile.Id)
	test.IsEqualBool(t, ok, true)
	_, err := ReplaceFile("invalidfile", originalFile.Id, false)
	test.IsNotNil(t, err)
	_, err = ReplaceFile(originalFile.Id, "invalidfile", false)
	test.IsNotNil(t, err)
	_, err = ReplaceFile(originalFile.Id, e2eFile.Id, false)
	test.IsNotNil(t, err)

	_, err = ReplaceFile(originalFile.Id, newFile.Id, false)
	test.IsNil(t, err)
	file, ok := GetFile(originalFile.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, file.Name, newFile.Name)
	test.IsEqualString(t, file.SHA1, newFile.SHA1)
	test.IsEqualString(t, file.ContentType, newFile.ContentType)
	test.IsEqualString(t, file.AwsBucket, newFile.AwsBucket)
	test.IsEqualString(t, file.Size, newFile.Size)
	test.IsEqualInt64(t, file.SizeBytes, newFile.SizeBytes)
	test.IsEqual(t, file.Encryption, newFile.Encryption)
	_, ok = GetFile(newFile.Id)
	test.IsEqualBool(t, ok, true)

	_, err = ReplaceFile(originalFile.Id, newFile.Id, true)
	_, ok = GetFile(originalFile.Id)
	test.IsEqualBool(t, ok, true)
	_, ok = GetFile(newFile.Id)
	test.IsEqualBool(t, ok, false)
}
func TestParallelDownloads(t *testing.T) {
	const allowedDownloads = 5

	singleDownloadFile := models.File{
		Id:                 "only5downloads",
		Name:               "only5downloads.txt",
		Size:               "1KB",
		SHA1:               "replacetest1",
		ContentType:        "text/plain",
		DownloadsRemaining: allowedDownloads,
		UnlimitedDownloads: false,
		UnlimitedTime:      true,
		AwsBucket:          "",
		SizeBytes:          1024,
		Encryption: models.EncryptionInfo{
			IsEncrypted:         false,
			IsEndToEndEncrypted: false,
			DecryptionKey:       nil,
			Nonce:               nil,
		},
	}
	database.SaveMetaData(singleDownloadFile)

	synctest.Test(t, func(t *testing.T) {
		const workers = 50
		results := make(chan bool, workers)

		for i := 0; i < workers; i++ {
			go func() {
				w := httptest.NewRecorder()
				r := httptest.NewRequest("GET", "/"+singleDownloadFile.Id, nil)

				// The mutex inside ServeFile should serialize the decrement logic.
				success := ServeFile(singleDownloadFile, w, r, false, true, false, true)
				results <- success
			}()
		}

		synctest.Wait()
		close(results)

		var successCount int
		var failureCount int

		for res := range results {
			if res {
				successCount++
			} else {
				failureCount++
			}
		}

		test.IsEqualInt(t, successCount, allowedDownloads)
		test.IsEqualInt(t, failureCount, workers-allowedDownloads)
	})
}

func TestServeFilesAsZipSanitisation(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)

	// Path traversal in the zip filename must be neutralised before it
	// reaches the Content-Disposition header.
	w := httptest.NewRecorder()
	ServeFilesAsZip([]models.File{}, "../../etc/evil", w, r)
	cd := w.Result().Header.Get("Content-Disposition")
	test.IsEqualBool(t, strings.HasPrefix(cd, ".."), false)
	test.IsEqualBool(t, strings.Contains(cd, "/"), false)
	// The header must still be a valid attachment directive.
	test.IsEqualBool(t, strings.HasPrefix(cd, "attachment;"), true)

	// CRLF in the zip filename must be stripped so it cannot split the
	// HTTP response and inject arbitrary headers.
	w = httptest.NewRecorder()
	ServeFilesAsZip([]models.File{}, "bundle\r\nX-Evil: injected", w, r)
	cd = w.Result().Header.Get("Content-Disposition")
	test.IsEqualBool(t, strings.Contains(cd, "\r"), false)
	test.IsEqualBool(t, strings.Contains(cd, "\n"), false)
	test.IsEqualString(t, r.Header.Get("X-Evil"), "")

	// Null byte in filename must be stripped.
	w = httptest.NewRecorder()
	ServeFilesAsZip([]models.File{}, "file\x00name", w, r)
	cd = w.Result().Header.Get("Content-Disposition")
	test.IsEqualBool(t, strings.Contains(cd, "\x00"), false)

	// An empty filename must fall back to "Gokapi" (the hardcoded default)
	// so the Content-Disposition header is always well-formed.
	w = httptest.NewRecorder()
	ServeFilesAsZip([]models.File{}, "", w, r)
	cd = w.Result().Header.Get("Content-Disposition")
	test.IsEqualBool(t, strings.Contains(cd, "Gokapi"), true)

	// A clean filename must be preserved exactly (plus the .zip suffix).
	w = httptest.NewRecorder()
	ServeFilesAsZip([]models.File{}, "my-archive", w, r)
	cd = w.Result().Header.Get("Content-Disposition")
	test.IsEqualBool(t, strings.Contains(cd, "my-archive.zip"), true)
}

// TestCleanUpRunsHotlinkPurge guards the wiring rather than the purge itself.
// purgeHotlinksIfDisabled only ever runs because CleanUp calls it, and CleanUp
// is what runs at startup and hourly, so dropping that call would silently
// leave every existing hotlink live with no other test noticing.
func TestCleanUpRunsHotlinkPurge(t *testing.T) {
	os.Unsetenv("GOKAPI_DISABLE_HOTLINKS")
	file := models.File{
		Id:                 "cleanuphotlinktest",
		Name:               "cleanuphotlinktest.jpg",
		SHA1:               "cleanuphotlinktest",
		ContentType:        "image/jpg",
		HotlinkId:          "cleanuphotlinktestlink.jpg",
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
	}
	// The blob has to exist, otherwise CleanUp removes the file as unavailable and
	// the hotlink would disappear as ordinary cleanup rather than as the purge,
	// which would make this test unable to tell the two apart.
	blobPath := configuration.Get().DataDir + "/" + file.SHA1
	err := os.WriteFile(blobPath, []byte("blob"), 0600)
	test.IsNil(t, err)
	defer os.Remove(blobPath)

	database.SaveMetaData(file)
	database.SaveHotlink(file)
	_, ok := database.GetHotlink(file.HotlinkId)
	test.IsEqualBool(t, ok, true)

	os.Setenv("GOKAPI_DISABLE_HOTLINKS", "true")
	defer os.Unsetenv("GOKAPI_DISABLE_HOTLINKS")

	CleanUp(false)

	_, ok = database.GetHotlink(file.HotlinkId)
	test.IsEqualBool(t, ok, false)
	storedFile, ok := database.GetMetaDataById(file.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, storedFile.HotlinkId, "")
}

// sealAtInputLevel configures the instance as sealed at a given Input encryption level (see
// encryption.Init/encryption.IsSealed) without ever deriving a real key - Init only records the
// salts and sets the sealed flag, it never runs scrypt, so this is cheap to call from a test.
// The returned func restores both the encryption level and the (unsealed, NoEncryption) instance
// state, and must be deferred by the caller so a sealed instance never leaks into a later test in
// this file.
func sealAtInputLevel(t *testing.T, level int, saltSuffix string) func() {
	t.Helper()
	previousLevel := configuration.Get().Encryption.Level
	configuration.Get().Encryption.Level = level
	encryption.Init(models.Configuration{Encryption: models.Encryption{
		Level:        level,
		Salt:         "storage-seal-test-salt-" + saltSuffix,
		ChecksumSalt: "storage-seal-test-checksum-salt-" + saltSuffix,
		Checksum:     "irrelevant-while-only-sealing",
	}})
	test.IsEqualBool(t, encryption.IsSealed(), true)
	return func() {
		configuration.Get().Encryption.Level = previousLevel
		encryption.Init(models.Configuration{Encryption: models.Encryption{Level: encryption.NoEncryption}})
	}
}

// TestNewFileSealedRefusesUpload is the "uploads refuse cleanly while sealed" requirement for a
// complete (non-chunked) upload: at an encryption level that needs the master key, NewFile must
// return ErrorInstanceSealed rather than panic deep inside generateHashAndEncrypt, which is what
// would happen if this reached encryption.Encrypt with no master key loaded (see
// encryption.fileCipherEncrypt).
func TestNewFileSealedRefusesUpload(t *testing.T) {
	defer sealAtInputLevel(t, encryption.FullEncryptionInput, "newfile")()

	content := []byte("sealed upload must be refused")
	header, request := createRawTestFile(content)
	_, err := NewFile(bytes.NewReader(content), &header, 99, request)
	test.IsEqualBool(t, errors.Is(err, ErrorInstanceSealed), true)
}

// TestNewFileFromChunkSealedRefusesUpload is the chunked-upload counterpart of
// TestNewFileSealedRefusesUpload: NewFileFromChunk must refuse the same way, before it ever
// touches the reserved chunk file on disk.
func TestNewFileFromChunkSealedRefusesUpload(t *testing.T) {
	defer sealAtInputLevel(t, encryption.FullEncryptionInput, "newfilefromchunk")()

	chunkId, header, request, err := createTestChunk()
	test.IsNil(t, err)
	defer os.Remove("test/data/chunk-" + chunkId)

	_, err = NewFileFromChunk(chunkId, header, 99, request)
	test.IsEqualBool(t, errors.Is(err, ErrorInstanceSealed), true)
}

// TestServeFileSealedRefusesDownload is the download half of the requirement: a server-side
// encrypted file must not be served while sealed. Mirrors
// TestServeFileAuditWriteFailureRefusesDownload's assertions exactly (handled == true, 503, and
// nothing served) - the response is committed directly inside ServeFile, so no caller
// additionally renders an "expired" page/image over the top of it.
func TestServeFileSealedRefusesDownload(t *testing.T) {
	defer sealAtInputLevel(t, encryption.FullEncryptionInput, "servefile")()

	file := models.File{
		Id:                 "sealedDownloadTestFile",
		Name:               "sealed.txt",
		Encryption:         models.EncryptionInfo{IsEncrypted: true},
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
	}
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handled := ServeFile(file, w, r, true, true, false, false)

	test.IsEqualBool(t, handled, true)
	test.IsEqualInt(t, w.Code, http.StatusServiceUnavailable)
	test.IsEqualBool(t, strings.Contains(w.Body.String(), file.Name), false)

	// An end-to-end encrypted file never touches the server's master key at all (the server
	// never holds a key capable of decrypting it), so it must not be blocked by the sealed check
	// above - only IsEncrypted && !IsEndToEndEncrypted is gated.
	e2eFile := models.File{
		Id:                 "sealedDownloadE2EFile",
		Name:               "sealed-e2e.txt",
		Encryption:         models.EncryptionInfo{IsEncrypted: true, IsEndToEndEncrypted: true},
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
	}
	database.SaveMetaData(e2eFile)
	r = httptest.NewRequest("GET", "/", nil)
	w = httptest.NewRecorder()
	handled = ServeFile(e2eFile, w, r, true, true, false, false)
	test.IsEqualBool(t, handled, true)
	test.IsEqualBool(t, w.Code == http.StatusServiceUnavailable, false)
}

// TestServeFilesAsZipSealedRefusesDownload is ServeFilesAsZip's counterpart to
// TestServeFileSealedRefusesDownload: a bundle containing a server-side encrypted member must be
// refused before the zip stream (and its 200 status) is ever started.
func TestServeFilesAsZipSealedRefusesDownload(t *testing.T) {
	defer sealAtInputLevel(t, encryption.FullEncryptionInput, "servefileszip")()

	files := []models.File{{
		Id:         "sealedZipTestFile",
		Name:       "sealed.txt",
		Encryption: models.EncryptionInfo{IsEncrypted: true},
	}}
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	ServeFilesAsZip(files, "bundle", w, r)

	test.IsEqualInt(t, w.Code, http.StatusServiceUnavailable)
}
