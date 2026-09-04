package models

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/test"
)

func TestToJsonResult(t *testing.T) {
	file := File{
		Id:                 "testId",
		Name:               "testName",
		Size:               "10 B",
		SizeBytes:          10,
		SHA1:               "sha256",
		ExpireAt:           1750852108,
		DownloadsRemaining: 1,
		PasswordHash:       "pwhash",
		HotlinkId:          "hotlinkid",
		ContentType:        "text/html",
		AwsBucket:          "test",
		UploadDate:         1748180908,
		UserId:             2,
		DownloadCount:      3,
		Encryption: EncryptionInfo{
			IsEncrypted:   true,
			DecryptionKey: []byte{0x01},
			Nonce:         []byte{0x02},
		},
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		PendingDeletion:    100,
	}
	test.IsEqualString(t, file.ToJsonResult("serverurl/", false, file.DownloadAccess(0)), `{"Result":"OK","FileInfo":{"Id":"testId","Name":"testName","Size":"10 B","HotlinkId":"hotlinkid","ContentType":"text/html","ExpireAtString":"2025-06-25 11:48:28","UrlDownload":"serverurl/d?id=testId","UrlHotlink":"","FileRequestId":"","BundleId":"","UploadDate":1748180908,"ExpireAt":1750852108,"SizeBytes":10,"DownloadsRemaining":1,"DownloadCount":3,"UnlimitedDownloads":true,"UnlimitedTime":true,"DisposedAt":0,"RequiresClientSideDecryption":true,"IsEncrypted":true,"IsEndToEndEncrypted":false,"IsPasswordProtected":true,"IsSavedOnLocalStorage":false,"Status":"deleted","AllowanceGoverning":"own","AllowanceRemaining":1,"AllowanceUnlimited":true,"IsFileRequest":false,"UploaderId":2},"IncludeFilename":false}`)
	test.IsEqualString(t, file.ToJsonResult("serverurl/", true, file.DownloadAccess(0)), `{"Result":"OK","FileInfo":{"Id":"testId","Name":"testName","Size":"10 B","HotlinkId":"hotlinkid","ContentType":"text/html","ExpireAtString":"2025-06-25 11:48:28","UrlDownload":"serverurl/d/testId/testName","UrlHotlink":"","FileRequestId":"","BundleId":"","UploadDate":1748180908,"ExpireAt":1750852108,"SizeBytes":10,"DownloadsRemaining":1,"DownloadCount":3,"UnlimitedDownloads":true,"UnlimitedTime":true,"DisposedAt":0,"RequiresClientSideDecryption":true,"IsEncrypted":true,"IsEndToEndEncrypted":false,"IsPasswordProtected":true,"IsSavedOnLocalStorage":false,"Status":"deleted","AllowanceGoverning":"own","AllowanceRemaining":1,"AllowanceUnlimited":true,"IsFileRequest":false,"UploaderId":2},"IncludeFilename":true}`)
}

// TestStatusPendingDeletionAlwaysMeansDeleted pins that a non-zero PendingDeletion reports
// StatusDeleted regardless of how far in the past its timestamp is. DeleteFile is the only writer
// of this field now that scheduled deletion is gone, and it always backdates - a future value can
// no longer legitimately occur - but the test sets one anyway, so that reintroducing a second,
// still-counting-down branch (what StatusPendingDeletion used to mean) fails here rather than
// going unnoticed.
func TestStatusPendingDeletionAlwaysMeansDeleted(t *testing.T) {
	pastFile := File{PendingDeletion: time.Now().Add(-time.Hour).Unix(), UnlimitedTime: true, UnlimitedDownloads: true}
	test.IsEqualString(t, pastFile.Status(pastFile.DownloadAccess(0), time.Now().Unix()), StatusDeleted)

	farPastFile := File{PendingDeletion: 1, UnlimitedTime: true, UnlimitedDownloads: true}
	test.IsEqualString(t, farPastFile.Status(farPastFile.DownloadAccess(0), time.Now().Unix()), StatusDeleted)

	futureFile := File{PendingDeletion: time.Now().Add(time.Hour).Unix(), UnlimitedTime: true, UnlimitedDownloads: true}
	test.IsEqualString(t, futureFile.Status(futureFile.DownloadAccess(0), time.Now().Unix()), StatusDeleted)
}

func TestIsLocalStorage(t *testing.T) {
	file := File{AwsBucket: "123"}
	test.IsEqualBool(t, file.IsLocalStorage(), false)
	file.AwsBucket = ""
	test.IsEqualBool(t, file.IsLocalStorage(), true)
}

func TestErrorAsJson(t *testing.T) {
	result := errorAsJson(errors.New("testerror"))
	test.IsEqualString(t, result, "{\"Result\":\"error\",\"ErrorMessage\":\"testerror\"}")
}

func TestRequiresClientDecryption(t *testing.T) {
	file := File{
		Id:        "test",
		AwsBucket: "bucket",
		Encryption: EncryptionInfo{
			IsEncrypted: true,
		},
	}
	test.IsEqualBool(t, file.RequiresClientDecryption(), true)
	file.Encryption.IsEncrypted = false
	test.IsEqualBool(t, file.RequiresClientDecryption(), false)
	file.AwsBucket = ""
	test.IsEqualBool(t, file.RequiresClientDecryption(), false)
	file.Encryption.IsEncrypted = true
	test.IsEqualBool(t, file.RequiresClientDecryption(), false)
}

func TestGetHolinkUrl(t *testing.T) {
	file := FileApiOutput{
		Id:                           "testfile",
		Name:                         "name",
		Size:                         "1 B",
		HotlinkId:                    "test",
		RequiresClientSideDecryption: true,
	}
	url := getHotlinkUrl(file, "testserver/", false)
	test.IsEqualString(t, url, "")
	file.RequiresClientSideDecryption = false
	url = getHotlinkUrl(file, "testserver/", false)
	test.IsEqualString(t, url, "testserver/h/test")
	file.HotlinkId = ""
	url = getHotlinkUrl(file, "testserver/", false)
	test.IsEqualString(t, url, "testserver/downloadFile?id=testfile")
	url = getHotlinkUrl(file, "testserver/", true)
	test.IsEqualString(t, url, "testserver/dh/testfile/name")
}

func TestToFileApiOutputFileRequest(t *testing.T) {
	file := File{
		Id:              "testId",
		Name:            "testName",
		UserId:          2,
		UploadRequestId: "requestId",
	}
	output, err := file.ToFileApiOutput("serverurl/", false, file.DownloadAccess(0))
	test.IsNil(t, err)
	test.IsEqualBool(t, output.IsFileRequest, true)
	// A file collected through a file request has no public share URL, but the
	// owner still has to be identifiable - the collect view lists files by uploader.
	test.IsEqualString(t, output.UrlDownload, "")
	test.IsEqualString(t, output.UrlHotlink, "")
	test.IsEqualInt(t, output.UploaderId, 2)
}

// TestToFileApiOutputDisposedAtCrossesApiBoundary guards the regression this file's DisposedAt
// field fixes: FileApiOutput used to lack the field entirely, so copier.Copy had nothing to
// populate and every client saw DisposedAt as absent, no matter what was stored.
func TestToFileApiOutputDisposedAtCrossesApiBoundary(t *testing.T) {
	file := File{
		Id:             "disposedFile",
		Name:           "disposedFile",
		UserId:         2,
		DisposedAt:     1750852108,
		DisposalReason: DisposalReasonExpired,
	}
	output, err := file.ToFileApiOutput("serverurl/", false, file.DownloadAccess(0))
	test.IsNil(t, err)
	test.IsEqualInt64(t, output.DisposedAt, file.DisposedAt)
}

func TestToFileApiOutputActiveFileHasZeroDisposedAt(t *testing.T) {
	file := File{
		Id:                 "activeFile",
		Name:               "activeFile",
		UserId:             2,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
	}
	output, err := file.ToFileApiOutput("serverurl/", false, file.DownloadAccess(0))
	test.IsNil(t, err)
	test.IsEqualInt64(t, output.DisposedAt, 0)
}

// TestWindowOpenedAtNeverCrossesApiBoundary pins a deliberate omission. WindowOpenedAt is when a
// file's download window opened, and the leeway that closes it is server configuration the
// uploader can neither set nor override per file (the one place it is published is
// /pubapi/config, as a policy statement to the person downloading). Copying it onto the API
// output would put a value on every file that looks like a setting and is not one.
func TestWindowOpenedAtNeverCrossesApiBoundary(t *testing.T) {
	file := File{
		Id:                 "windowfile",
		Name:               "window.dat",
		SHA1:               "sha1",
		ExpireAt:           1750852108,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		WindowOpenedAt:     1750852000,
	}
	output, err := file.ToFileApiOutput("serverurl/", false, file.DownloadAccess(0))
	test.IsNil(t, err)
	encoded, err := json.Marshal(output)
	test.IsNil(t, err)
	test.IsEqualBool(t, strings.Contains(strings.ToLower(string(encoded)), "windowopenedat"), false)
	test.IsEqualBool(t, strings.Contains(string(encoded), "1750852000"), false)
}
