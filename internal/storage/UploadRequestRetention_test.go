//go:build !integration && test

package storage

import (
	"os"
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/test"
)

// This file tests the file request retention sweep (cleanExpiredFileRequests, called from
// CleanUp): a file request that has outlived GOKAPI_FILEREQUEST_RETENTION after expiring or being
// closed is deleted along with every file it received and its upload API key, routed through
// DeleteFileRequest - see that function's doc comment for why the cascade lives in this package
// rather than storage/filerequest. Retention 0, the default, must delete nothing, ever.

// setFileRequestRetention overrides GOKAPI_FILEREQUEST_RETENTION for the calling test, restoring
// this package's test default (retention disabled) once it finishes. Safe against the other tests
// in this package for the same reason MetadataRetention_test.go's setRetention is: none of them
// run under t.Parallel(), so a non-parallel test always runs to completion, restore included,
// before the next one starts.
func setFileRequestRetention(t *testing.T, value string) {
	t.Helper()
	os.Setenv("GOKAPI_FILEREQUEST_RETENTION", value)
	t.Cleanup(func() { os.Setenv("GOKAPI_FILEREQUEST_RETENTION", "0") })
}

// saveFileRequestFixture stores request, one file it received, and its upload API key (request.
// ApiKey must already be set by the caller). The owner is always the test admin user (Id 5, see
// testconfiguration's writeUsers): a request owned by a nonexistent user would be removed by
// cleanInvalidFileRequests regardless of retention, which would prove nothing about the sweep
// under test here. PublicId is set to a value unique to the request, since the ApiKeys table
// enforces uniqueness on it and every fixture in this suite otherwise defaults it to "".
func saveFileRequestFixture(t *testing.T, request models.FileRequest) models.FileRequest {
	t.Helper()
	request.UserId = 5
	database.SaveFileRequest(request)
	// A real blob, not just a metadata row: CleanUp's branch 4 ("stored content missing") hard
	// deletes any row whose SHA1 does not resolve to a file on disk, bypassing retention
	// entirely - see writeBlob's own comment. Without this every fixture here would vanish in the
	// very first CleanUp pass regardless of what this suite is actually testing.
	sha1 := writeBlob(t, "filerequest-retention-fixture")
	database.SaveMetaData(models.File{
		Id:                 request.Id + "_file",
		Name:               request.Id + ".txt",
		SHA1:               sha1,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		UploadRequestId:    request.Id,
	})
	database.SaveApiKey(models.ApiKey{
		Id:              request.ApiKey,
		PublicId:        request.Id + "_pub",
		UserId:          5,
		UploadRequestId: request.Id,
	})
	return request
}

// TestCleanUpFileRequestRetentionZeroDeletesNothing is the regression guard the task calls out
// explicitly: retention disabled must never delete a file request, no matter how long ago it
// expired or closed.
func TestCleanUpFileRequestRetentionZeroDeletesNothing(t *testing.T) {
	setFileRequestRetention(t, "0")

	idExpired := "frretzeroexpired_" + helper.GenerateRandomString(8)
	requestExpired := saveFileRequestFixture(t, models.FileRequest{
		Id:     idExpired,
		ApiKey: idExpired + "_key",
		Expiry: time.Now().Add(-365 * 24 * time.Hour).Unix(),
	})

	idClosed := "frretzeroclosed_" + helper.GenerateRandomString(8)
	requestClosed := saveFileRequestFixture(t, models.FileRequest{
		Id:       idClosed,
		ApiKey:   idClosed + "_key",
		Closed:   true,
		ClosedAt: time.Now().Add(-365 * 24 * time.Hour).Unix(),
	})

	CleanUp(false)

	for _, request := range []models.FileRequest{requestExpired, requestClosed} {
		_, ok := database.GetFileRequest(request.Id)
		test.IsEqualBool(t, ok, true)
		_, ok = database.GetApiKey(request.ApiKey)
		test.IsEqualBool(t, ok, true)
		stored, ok := database.GetMetaDataById(request.Id + "_file")
		test.IsEqualBool(t, ok, true)
		test.IsEqualInt64(t, stored.PendingDeletion, 0)
	}
}

// TestCleanUpDeletesFileRequestExpiredPastRetention is the other half of the task's explicit
// guard: a request expired for longer than the retention period is deleted, and so is every file
// it received and its upload API key - the DeleteFileRequest cascade, not a partial cleanup.
func TestCleanUpDeletesFileRequestExpiredPastRetention(t *testing.T) {
	setFileRequestRetention(t, "1h")
	id := "frretexpired_" + helper.GenerateRandomString(8)
	request := saveFileRequestFixture(t, models.FileRequest{
		Id:     id,
		ApiKey: id + "_key",
		Expiry: time.Now().Add(-2 * time.Hour).Unix(),
	})

	CleanUp(false)
	// DeleteFileRequest routes its files through DeleteFiles(files, true), which - like every
	// deleteSource=true caller in this package, see TestDeleteFile - schedules a second,
	// asynchronous CleanUp pass rather than disposing them inline. Waiting it out here, the same
	// way TestDeleteFile does after each of its own deleteSource=true calls, is what keeps that
	// pass from firing during a later test and racing FileServing_test.go's TestCleanUp, which
	// depends on nothing having swept its fixtures before its own first CleanUp(false) call.
	time.Sleep(time.Second)

	_, ok := database.GetFileRequest(request.Id)
	test.IsEqualBool(t, ok, false)
	_, ok = database.GetApiKey(request.ApiKey)
	test.IsEqualBool(t, ok, false)
	// GOKAPI_METADATA_RETENTION defaults to 0 in this suite (see testconfiguration.SetDirEnv), so
	// the asynchronous CleanUp pass above both disposes of and purges the row in the same sweep,
	// rather than leaving a disposed record behind.
	_, ok = database.GetMetaDataById(request.Id + "_file")
	test.IsEqualBool(t, ok, false)
}

// TestCleanUpKeepsFileRequestExpiredWithinRetention is the boundary case: expired, but not yet
// past the retention window, must survive untouched.
func TestCleanUpKeepsFileRequestExpiredWithinRetention(t *testing.T) {
	setFileRequestRetention(t, "24h")
	id := "frretwithin_" + helper.GenerateRandomString(8)
	request := saveFileRequestFixture(t, models.FileRequest{
		Id:     id,
		ApiKey: id + "_key",
		Expiry: time.Now().Add(-time.Minute).Unix(),
	})

	CleanUp(false)

	_, ok := database.GetFileRequest(request.Id)
	test.IsEqualBool(t, ok, true)
	_, ok = database.GetApiKey(request.ApiKey)
	test.IsEqualBool(t, ok, true)
	stored, ok := database.GetMetaDataById(request.Id + "_file")
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt64(t, stored.PendingDeletion, 0)
}

// TestCleanUpDeletesClosedFileRequestPastRetention proves the closed path independently of
// expiry: Expiry is left at its unlimited zero value, so only ClosedAt can explain the deletion.
func TestCleanUpDeletesClosedFileRequestPastRetention(t *testing.T) {
	setFileRequestRetention(t, "1h")
	id := "frretclosed_" + helper.GenerateRandomString(8)
	request := saveFileRequestFixture(t, models.FileRequest{
		Id:       id,
		ApiKey:   id + "_key",
		Closed:   true,
		ClosedAt: time.Now().Add(-2 * time.Hour).Unix(),
	})

	CleanUp(false)
	// See the identical wait in TestCleanUpDeletesFileRequestExpiredPastRetention: DeleteFileRequest
	// schedules a second, asynchronous CleanUp pass for its files rather than disposing them inline.
	time.Sleep(time.Second)

	_, ok := database.GetFileRequest(request.Id)
	test.IsEqualBool(t, ok, false)
	_, ok = database.GetApiKey(request.ApiKey)
	test.IsEqualBool(t, ok, false)
	_, ok = database.GetMetaDataById(request.Id + "_file")
	test.IsEqualBool(t, ok, false)
}

// TestCleanUpKeepsClosedFileRequestWithinRetentionOfClosing is "a closed-but-not-expired request
// is measured from when it closed", proven the way that claim actually needs proving: CreationDate
// is old enough that measuring from it would fail the request, while ClosedAt is recent enough
// that measuring from it lets the request survive.
func TestCleanUpKeepsClosedFileRequestWithinRetentionOfClosing(t *testing.T) {
	setFileRequestRetention(t, "24h")
	id := "frretclosedwithin_" + helper.GenerateRandomString(8)
	request := saveFileRequestFixture(t, models.FileRequest{
		Id:           id,
		ApiKey:       id + "_key",
		CreationDate: time.Now().Add(-30 * 24 * time.Hour).Unix(),
		Closed:       true,
		ClosedAt:     time.Now().Add(-time.Minute).Unix(),
	})

	CleanUp(false)

	_, ok := database.GetFileRequest(request.Id)
	test.IsEqualBool(t, ok, true)
}

// TestCleanUpKeepsClosedFileRequestWithZeroClosedAt guards the design decision documented on
// models.FileRequest.ClosedAt: a request closed before this field existed reads back ClosedAt == 0
// (the migration's backfill default), and 0 means "unknown", not "closed at the epoch" - such a
// request must be left alone by the closed path rather than deleted the moment retention is turned
// on.
func TestCleanUpKeepsClosedFileRequestWithZeroClosedAt(t *testing.T) {
	setFileRequestRetention(t, "1h")
	id := "frretlegacyclosed_" + helper.GenerateRandomString(8)
	request := saveFileRequestFixture(t, models.FileRequest{
		Id:     id,
		ApiKey: id + "_key",
		Closed: true,
	})

	CleanUp(false)

	_, ok := database.GetFileRequest(request.Id)
	test.IsEqualBool(t, ok, true)
}
