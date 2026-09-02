package api

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/helper"
	gokapimail "github.com/forceu/gokapi/internal/mail"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/storage"
	"github.com/forceu/gokapi/internal/storage/filebundle"
	"github.com/forceu/gokapi/internal/test"
)

// writeTestChunk writes a chunk's content directly to where /chunk/add would have left it,
// the same technique TestChunkCompleteRejectsE2EWhenNotConfigured uses, so each test below can
// go straight to /chunk/complete without a separate /chunk/add round trip. Content is always
// "test" (4 bytes), matching the "filesize" header every test in this file uses.
func writeTestChunk(t *testing.T, uuid string) {
	t.Helper()
	test.IsNil(t, os.WriteFile("test/data/chunk-"+uuid, []byte("test"), 0600))
}

// This file covers the 2026-09-02 audit decision documented in
// docs/superpowers/plans/2026-09-02-audit-fix-decisions.md, item 1: a
// recipient-only share must never have a window where it exists with no
// password and no grants. The fix makes /api/chunk/complete's "recipients"
// header part of the same request that creates the file: grants are created
// before the upload is confirmed, and a grant failure rolls the file back
// rather than leaving it reachable with no protection.

// enableMail configures a working (log) mail connector, so shareaccess.GrantAccess can succeed.
func enableMail(t *testing.T) {
	t.Helper()
	test.IsNil(t, gokapimail.InitWithConfig(gokapimail.Config{
		Provider: gokapimail.ProviderLog, TimeoutSeconds: 20,
	}))
	t.Cleanup(func() { gokapimail.ResetForTesting() })
}

// enableFailingMail configures a connector that is "enabled" (so GrantAccess proceeds past its
// ErrMailNotConfigured check and creates the grants) but whose Send always fails: SMTP pointed at
// a loopback port nothing listens on, so the dial is refused immediately and deterministically,
// with no real network access required.
func enableFailingMail(t *testing.T) {
	t.Helper()
	test.IsNil(t, gokapimail.InitWithConfig(gokapimail.Config{
		Provider:          gokapimail.ProviderSmtp,
		FromAddress:       "noreply@example.com",
		SmtpHost:          "127.0.0.1",
		SmtpPort:          1,
		SmtpEncryption:    gokapimail.EncryptionNone,
		SmtpAllowInsecure: true,
		TimeoutSeconds:    2,
	}))
	t.Cleanup(func() { gokapimail.ResetForTesting() })
}

// chunkCompleteResponse mirrors outputFileJsonWithRecipients' shape, for unmarshalling in tests.
type chunkCompleteResponse struct {
	Result     string                         `json:"Result"`
	FileInfo   models.FileApiOutput           `json:"FileInfo"`
	Recipients []chunkCompleteRecipientOutput `json:"recipients"`
}

func uploadKeyForChunkCompleteTests(t *testing.T) models.ApiKey {
	t.Helper()
	apiKey := generateNewKey(false, idUser, "", "")
	apiKey.GrantPermission(models.ApiPermUpload)
	database.SaveApiKey(apiKey)
	return apiKey
}

// TestChunkCompleteWithRecipients_CreatesFileAndGrants proves the core happy path: a single
// file uploaded with a recipients header exists afterwards, AND its grants exist - both created
// by the one request, matching Ming's atomic decision.
func TestChunkCompleteWithRecipients_CreatesFileAndGrants(t *testing.T) {
	enableMail(t)
	apiKey := uploadKeyForChunkCompleteTests(t)
	writeTestChunk(t, "atomicshare-single-ok")

	w, r := test.GetRecorder("POST", "/api/chunk/complete", nil, []test.Header{
		{Name: "apikey", Value: apiKey.Id},
		{Name: "uuid", Value: "atomicshare-single-ok"},
		{Name: "filename", Value: "atomic-share-ok.txt"},
		{Name: "filesize", Value: "4"},
		{Name: "recipients", Value: "person@example.com"},
	}, nil)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)

	body, err := io.ReadAll(w.Result().Body)
	test.IsNil(t, err)
	var result chunkCompleteResponse
	test.IsNil(t, json.Unmarshal(body, &result))
	test.IsEqualString(t, result.Result, "OK")
	fileId := result.FileInfo.Id
	if fileId == "" {
		t.Fatal("no file id returned")
	}

	// The file itself exists.
	_, found := storage.GetFile(fileId)
	test.IsEqualBool(t, found, true)

	// The grant exists, and was reported back on the same response.
	test.IsEqualBool(t, database.IsShareRestricted(models.ShareResourceFile, fileId), true)
	if len(result.Recipients) != 1 || result.Recipients[0].Email != "person@example.com" {
		t.Fatalf("expected one reported recipient for person@example.com, got %+v", result.Recipients)
	}
	test.IsEqualString(t, result.Recipients[0].MailError, "")
}

// TestChunkCompleteRecipientGrantFailure_LeavesNoReachableFile is the central test for this
// item: when the grants cannot be created (here, no mail connector configured), the upload must
// fail AND nothing reachable may be left behind. It asserts this positively, at the same
// database layer resolveShareResource and the public download path both use to decide whether
// an id exists (storage.GetFile / database.GetAllMetadata) - not merely that the HTTP call
// returned an error. The uploaded file's id is never returned to the client on this failure
// path (the response never reaches FileInfo), which is itself part of the point: nothing about
// this response can be used to reach the file, because there is no file to reach.
func TestChunkCompleteRecipientGrantFailure_LeavesNoReachableFile(t *testing.T) {
	gokapimail.ResetForTesting() // no mail connector configured
	apiKey := uploadKeyForChunkCompleteTests(t)

	distinctiveName := "atomic-share-grant-fail-c1a9f2.txt"
	writeTestChunk(t, "atomicshare-single-failgrant")

	w, r := test.GetRecorder("POST", "/api/chunk/complete", nil, []test.Header{
		{Name: "apikey", Value: apiKey.Id},
		{Name: "uuid", Value: "atomicshare-single-failgrant"},
		{Name: "filename", Value: distinctiveName},
		{Name: "filesize", Value: "4"},
		{Name: "recipients", Value: "person@example.com"},
	}, nil)
	Process(w, r)

	// The upload itself must be refused, not just the recipient grant.
	test.IsEqualInt(t, w.Code, http.StatusPreconditionFailed)

	// deleteUnreachableUpload uses the same storage.DeleteFile(id, true) the pre-existing
	// audit-failure rollback uses: it marks the row PendingDeletion and schedules an async purge
	// (see storage.DeleteFile), rather than removing the database row synchronously. So the row
	// can still be present here - the row's mere existence is not the thing that matters. What
	// matters, and what is asserted below, is that it is not reachable: PendingDeletion must be
	// set, and storage.GetFile - the exact lookup resolveShareResource's own comment says the
	// public file endpoint relies on - must refuse it.
	found := false
	for id, file := range database.GetAllMetadata() {
		if file.Name != distinctiveName {
			continue
		}
		found = true
		if file.PendingDeletion == 0 {
			t.Fatalf("file %q (id %s) survived a failed grant with no rollback applied", distinctiveName, id)
		}
		if _, reachable := storage.GetFile(id); reachable {
			t.Fatalf("file %q (id %s) is still reachable via storage.GetFile after a failed grant", distinctiveName, id)
		}
	}
	if !found {
		// Also acceptable: the async purge already ran and removed the row entirely. Either way
		// there is nothing left for a caller to reach.
		t.Log("row for the failed upload was already purged by the time the test checked - also correct")
	}
}

// TestChunkCompleteNoRecipients_Unchanged is the regression guard: an upload with no recipients
// header must behave exactly as it did before this item - same response shape (no "recipients"
// key at all), no grants created.
func TestChunkCompleteNoRecipients_Unchanged(t *testing.T) {
	apiKey := uploadKeyForChunkCompleteTests(t)
	writeTestChunk(t, "atomicshare-single-norecipients")

	w, r := test.GetRecorder("POST", "/api/chunk/complete", nil, []test.Header{
		{Name: "apikey", Value: apiKey.Id},
		{Name: "uuid", Value: "atomicshare-single-norecipients"},
		{Name: "filename", Value: "atomic-share-no-recipients.txt"},
		{Name: "filesize", Value: "4"},
	}, nil)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)

	body, err := io.ReadAll(w.Result().Body)
	test.IsNil(t, err)
	// No "recipients" key at all - not even an empty array - confirming the response shape for
	// a plain upload is untouched by this item.
	var raw map[string]json.RawMessage
	test.IsNil(t, json.Unmarshal(body, &raw))
	if _, present := raw["recipients"]; present {
		t.Fatalf("a plain upload's response must not carry a \"recipients\" key, got: %s", body)
	}

	var result chunkCompleteResponse
	test.IsNil(t, json.Unmarshal(body, &result))
	test.IsEqualBool(t, database.IsShareRestricted(models.ShareResourceFile, result.FileInfo.Id), false)
}

// TestChunkCompleteBundleWithRecipients_GrantsAppliedToBundle proves the bundle case: a member
// file uploaded with a bundleid and a recipients header restricts the BUNDLE (matching how the
// SPA has always applied one grant to the whole folder, and how FileServing gates a member on
// its bundle's restriction), not the member file itself.
func TestChunkCompleteBundleWithRecipients_GrantsAppliedToBundle(t *testing.T) {
	enableMail(t)
	apiKey := uploadKeyForChunkCompleteTests(t)
	bundle := filebundle.Create("AtomicShareTestBundle_"+helper.GenerateRandomString(8), idUser)
	writeTestChunk(t, "atomicshare-bundle-member1")

	w, r := test.GetRecorder("POST", "/api/chunk/complete", nil, []test.Header{
		{Name: "apikey", Value: apiKey.Id},
		{Name: "uuid", Value: "atomicshare-bundle-member1"},
		{Name: "filename", Value: "atomic-share-bundle-member1.txt"},
		{Name: "filesize", Value: "4"},
		{Name: "bundleid", Value: bundle.Id},
		{Name: "recipients", Value: "person@example.com"},
	}, nil)
	Process(w, r)
	test.IsEqualInt(t, w.Code, 200)

	body, err := io.ReadAll(w.Result().Body)
	test.IsNil(t, err)
	var result chunkCompleteResponse
	test.IsNil(t, json.Unmarshal(body, &result))

	// The bundle carries the restriction, not the member file.
	test.IsEqualBool(t, database.IsShareRestricted(models.ShareResourceBundle, bundle.Id), true)
	test.IsEqualBool(t, database.IsShareRestricted(models.ShareResourceFile, result.FileInfo.Id), false)

	// A second member of the same bundle, sent with the same recipients header, must not
	// re-grant (and so not re-mail) the bundle - it rides on the restriction the first member
	// already established, and is reported back with an empty (not absent) recipients list.
	writeTestChunk(t, "atomicshare-bundle-member2")
	w2, r2 := test.GetRecorder("POST", "/api/chunk/complete", nil, []test.Header{
		{Name: "apikey", Value: apiKey.Id},
		{Name: "uuid", Value: "atomicshare-bundle-member2"},
		{Name: "filename", Value: "atomic-share-bundle-member2.txt"},
		{Name: "filesize", Value: "4"},
		{Name: "bundleid", Value: bundle.Id},
		{Name: "recipients", Value: "person@example.com"},
	}, nil)
	Process(w2, r2)
	test.IsEqualInt(t, w2.Code, 200)
	body2, err := io.ReadAll(w2.Result().Body)
	test.IsNil(t, err)
	var result2 chunkCompleteResponse
	test.IsNil(t, json.Unmarshal(body2, &result2))
	test.IsEqualInt(t, len(result2.Recipients), 0)
}

// TestChunkCompleteMailFailureAfterGrantsCreated_DoesNotFailUpload proves the second half of
// Ming's decision: once the grants exist, a mail delivery failure is harmless - the restriction
// is already in force and the link can be resent - so it must not fail the upload, only be
// visible in the response.
func TestChunkCompleteMailFailureAfterGrantsCreated_DoesNotFailUpload(t *testing.T) {
	enableFailingMail(t)
	apiKey := uploadKeyForChunkCompleteTests(t)
	writeTestChunk(t, "atomicshare-single-mailfail")

	w, r := test.GetRecorder("POST", "/api/chunk/complete", nil, []test.Header{
		{Name: "apikey", Value: apiKey.Id},
		{Name: "uuid", Value: "atomicshare-single-mailfail"},
		{Name: "filename", Value: "atomic-share-mailfail.txt"},
		{Name: "filesize", Value: "4"},
		{Name: "recipients", Value: "person@example.com"},
	}, nil)
	Process(w, r)

	// The upload succeeds...
	test.IsEqualInt(t, w.Code, 200)
	body, err := io.ReadAll(w.Result().Body)
	test.IsNil(t, err)
	var result chunkCompleteResponse
	test.IsNil(t, json.Unmarshal(body, &result))

	// ...the grant was still created...
	test.IsEqualBool(t, database.IsShareRestricted(models.ShareResourceFile, result.FileInfo.Id), true)
	_, found := storage.GetFile(result.FileInfo.Id)
	test.IsEqualBool(t, found, true)

	// ...and the mail failure is visible on the response, not swallowed.
	if len(result.Recipients) != 1 {
		t.Fatalf("expected one reported recipient, got %+v", result.Recipients)
	}
	if result.Recipients[0].MailError == "" {
		t.Fatal("expected a non-empty mailError for a delivery that could not connect")
	}
}
