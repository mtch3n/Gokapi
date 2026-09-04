//go:build !integration && test

package storage

import (
	"os"
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/encryption"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/test"
)

// This file tests the metadata retention feature end to end: a disposed record must be
// indistinguishable, on every public path, from one that was deleted outright (see the
// invariant tests in the webserver package for that half); a disposed record must still be
// exactly reconstructible history for its owner, meaning its stored name survives disposal even
// while the instance is sealed; storage.CleanUp's five-branch sweep and its shaRefCount
// deduplication must each behave exactly as documented; and DeleteFile must route an
// already-disposed record to a purge and a live one to disposal.

// writeBlob creates a uniquely-named content blob in the test data directory and returns the
// name to use as a file's SHA1 - the tests here never need the bytes to actually hash to the
// name, only for a file to exist there under that name, so a random id serves as both and
// guarantees no collision with another test's blob or the shared fixture blobs.
func writeBlob(t *testing.T, content string) string {
	t.Helper()
	sha1 := "disposaltest_" + helper.GenerateRandomString(16)
	err := os.WriteFile(configuration.Get().DataDir+"/"+sha1, []byte(content), 0600)
	test.IsNil(t, err)
	return sha1
}

// setRetention overrides GOKAPI_METADATA_RETENTION for the calling test, restoring this
// package's test default (retention disabled, see testconfiguration.SetDirEnv) once it finishes.
// Safe against the other tests in this package, none of which run under t.Parallel(): a
// non-parallel test always runs to completion, restore included, before the next one starts.
func setRetention(t *testing.T, value string) {
	t.Helper()
	os.Setenv("GOKAPI_METADATA_RETENTION", value)
	t.Cleanup(func() { os.Setenv("GOKAPI_METADATA_RETENTION", "0") })
}

// --- CleanUp sweep branch 1: pending deletion timer elapsed -> dispose, reason "deleted" ---

func TestCleanUpDisposesPendingDeletionTimerElapsed(t *testing.T) {
	setRetention(t, "24h")
	sha1 := writeBlob(t, "branch1")
	id := "branch1_" + helper.GenerateRandomString(8)
	database.SaveMetaData(models.File{
		Id:                 id,
		Name:               "branch1.txt",
		SHA1:               sha1,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		PendingDeletion:    time.Now().Add(-time.Hour).Unix(),
	})

	CleanUp(false)

	stored, ok := database.GetMetaDataById(id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, stored.IsDisposed(), true)
	test.IsEqualInt(t, stored.DisposalReason, models.DisposalReasonDeleted)
	test.FileDoesNotExist(t, configuration.Get().DataDir+"/"+sha1)
}

// --- CleanUp sweep branch 2: already disposed, past retention -> purge ---

func TestCleanUpPurgesDisposedRecordPastRetention(t *testing.T) {
	setRetention(t, "1h")
	id := "branch2_" + helper.GenerateRandomString(8)
	database.SaveMetaData(models.File{
		Id:                 id,
		Name:               "branch2.txt",
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		DisposedAt:         time.Now().Add(-2 * time.Hour).Unix(),
		DisposalReason:     models.DisposalReasonExpired,
	})

	CleanUp(false)

	_, ok := database.GetMetaDataById(id)
	test.IsEqualBool(t, ok, false)
}

// --- CleanUp sweep branch 3: already disposed, not yet past retention -> skipped entirely ---

func TestCleanUpSkipsDisposedRecordWithinRetention(t *testing.T) {
	setRetention(t, "24h")
	id := "branch3_" + helper.GenerateRandomString(8)
	database.SaveMetaData(models.File{
		Id:                 id,
		Name:               "branch3.txt",
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		DisposedAt:         time.Now().Add(-time.Minute).Unix(),
		DisposalReason:     models.DisposalReasonDownloaded,
	})

	CleanUp(false)

	stored, ok := database.GetMetaDataById(id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, stored.IsDisposed(), true)
	test.IsEqualInt(t, stored.DisposalReason, models.DisposalReasonDownloaded)
}

// --- CleanUp sweep branch 4: stored content missing -> hard delete, bypassing retention ---

func TestCleanUpHardDeletesMissingContent(t *testing.T) {
	setRetention(t, "24h")
	id := "branch4_" + helper.GenerateRandomString(8)
	database.SaveMetaData(models.File{
		Id:                 id,
		Name:               "branch4.txt",
		SHA1:               "branch4missing_" + helper.GenerateRandomString(8), // never written to disk
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
	})

	CleanUp(false)

	// Corruption is not history: a file whose content vanished out from under it (not through
	// CleanUp's own disposal) must not be kept as a disposed record, retention or not.
	_, ok := database.GetMetaDataById(id)
	test.IsEqualBool(t, ok, false)
}

// --- CleanUp sweep branch 5: expired / downloads exhausted -> dispose, right reason each ---

func TestCleanUpDisposesExpiredAndDownloadsExhausted(t *testing.T) {
	setRetention(t, "24h")

	sha1Expired := writeBlob(t, "expired-content")
	idExpired := "branch5expired_" + helper.GenerateRandomString(8)
	database.SaveMetaData(models.File{
		Id:                 idExpired,
		Name:               "expired.txt",
		SHA1:               sha1Expired,
		ExpireAt:           time.Now().Add(-time.Hour).Unix(),
		UnlimitedDownloads: true,
	})

	sha1Exhausted := writeBlob(t, "exhausted-content")
	idExhausted := "branch5exhausted_" + helper.GenerateRandomString(8)
	database.SaveMetaData(models.File{
		Id:                 idExhausted,
		Name:               "exhausted.txt",
		SHA1:               sha1Exhausted,
		UnlimitedTime:      true,
		DownloadsRemaining: 0,
	})

	CleanUp(false)

	storedExpired, ok := database.GetMetaDataById(idExpired)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, storedExpired.IsDisposed(), true)
	test.IsEqualInt(t, storedExpired.DisposalReason, models.DisposalReasonExpired)

	storedExhausted, ok := database.GetMetaDataById(idExhausted)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, storedExhausted.IsDisposed(), true)
	test.IsEqualInt(t, storedExhausted.DisposalReason, models.DisposalReasonDownloaded)
}

// TestCleanUpRetentionZeroPurgesInSamePass is the regression guard called out explicitly in the
// task: retention disabled must reproduce the pre-retention behaviour exactly, meaning dispose
// and purge both happen within a SINGLE CleanUp pass, not "disposed now, purged on some later
// pass". Every pre-existing CleanUp/DeleteFile test in this package relies on exactly this.
func TestCleanUpRetentionZeroPurgesInSamePass(t *testing.T) {
	setRetention(t, "0")
	sha1 := writeBlob(t, "retentionzero")
	id := "branch5zero_" + helper.GenerateRandomString(8)
	database.SaveMetaData(models.File{
		Id:                 id,
		Name:               "retentionzero.txt",
		SHA1:               sha1,
		ExpireAt:           time.Now().Add(-time.Hour).Unix(),
		UnlimitedDownloads: true,
	})

	CleanUp(false)

	_, ok := database.GetMetaDataById(id)
	test.IsEqualBool(t, ok, false)
	test.FileDoesNotExist(t, configuration.Get().DataDir+"/"+sha1)
}

// --- shaRefCount: a disposed row must not protect a blob; a live duplicate still must ---

// TestCleanUpShaRefCountDisposedRowDoesNotProtectBlob guards the replacement for the old O(n^2)
// dedup scan: shaRefCount is built by skipping every row for which IsDisposed() is true,
// regardless of what its SHA1 field still holds - not by relying on disposal having already
// blanked SHA1 (which real disposeFile does, but this constructs the row directly to prove the
// count itself, not disposeFile's redaction, is what keeps the row from counting). Without that
// exclusion, this row would wrongly be counted as a second reference and the blob would leak.
func TestCleanUpShaRefCountDisposedRowDoesNotProtectBlob(t *testing.T) {
	setRetention(t, "24h")
	sha1 := writeBlob(t, "shared-blob-disposed")

	idAlreadyDisposed := "refcount_disposed_" + helper.GenerateRandomString(8)
	database.SaveMetaData(models.File{
		Id:             idAlreadyDisposed,
		Name:           "disposed-sharer.txt",
		SHA1:           sha1,
		DisposedAt:     time.Now().Add(-time.Minute).Unix(),
		DisposalReason: models.DisposalReasonExpired,
	})

	idExpiring := "refcount_expiring_" + helper.GenerateRandomString(8)
	database.SaveMetaData(models.File{
		Id:                 idExpiring,
		Name:               "expiring.txt",
		SHA1:               sha1,
		ExpireAt:           time.Now().Add(-time.Hour).Unix(),
		UnlimitedDownloads: true,
	})

	CleanUp(false)

	test.FileDoesNotExist(t, configuration.Get().DataDir+"/"+sha1)
}

// TestCleanUpShaRefCountLiveDuplicateProtectsBlob is the positive counterpart: a still-live row
// sharing the blob must keep it, even though its sibling disposes of in the very same pass.
func TestCleanUpShaRefCountLiveDuplicateProtectsBlob(t *testing.T) {
	setRetention(t, "24h")
	sha1 := writeBlob(t, "shared-blob-live")

	idLive := "refcount_live_" + helper.GenerateRandomString(8)
	database.SaveMetaData(models.File{
		Id:                 idLive,
		Name:               "live.txt",
		SHA1:               sha1,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
	})

	idExpiring := "refcount_expiring2_" + helper.GenerateRandomString(8)
	database.SaveMetaData(models.File{
		Id:                 idExpiring,
		Name:               "expiring2.txt",
		SHA1:               sha1,
		ExpireAt:           time.Now().Add(-time.Hour).Unix(),
		UnlimitedDownloads: true,
	})

	CleanUp(false)

	test.FileExists(t, configuration.Get().DataDir+"/"+sha1)

	storedExpiring, ok := database.GetMetaDataById(idExpiring)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, storedExpiring.IsDisposed(), true)
	test.IsEqualString(t, storedExpiring.SHA1, "")

	storedLive, ok := database.GetMetaDataById(idLive)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, storedLive.IsDisposed(), false)
}

// --- DeleteFile: purges an already-disposed record, disposes a live one ---

func TestDeleteFilePurgesAlreadyDisposedRecord(t *testing.T) {
	id := "delete_disposed_" + helper.GenerateRandomString(8)
	database.SaveMetaData(models.File{
		Id:             id,
		Name:           "delete-disposed.txt",
		DisposedAt:     time.Now().Add(-time.Minute).Unix(),
		DisposalReason: models.DisposalReasonExpired,
	})

	result := DeleteFile(id, false)
	test.IsEqualBool(t, result, true)

	_, ok := database.GetMetaDataById(id)
	test.IsEqualBool(t, ok, false)
}

func TestDeleteFileDisposesLiveRecordRatherThanPurging(t *testing.T) {
	id := "delete_live_" + helper.GenerateRandomString(8)
	database.SaveMetaData(models.File{
		Id:                 id,
		Name:               "delete-live.txt",
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
	})

	result := DeleteFile(id, false)
	test.IsEqualBool(t, result, true)

	stored, ok := database.GetMetaDataById(id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, stored.IsDisposed(), false)
	test.IsEqualBool(t, stored.PendingDeletion != 0, true)
}

// --- Disposal clears every secret and revokes recipient login tokens ---

// TestDisposeClearsSecretsAndRevokesShareTokens drives a real disposal (through CleanUp, not a
// hand-simulated one) of a file carrying every kind of secret disposeFile is documented to clear,
// plus a hotlink and a share grant with an issued login token, and checks all of it: the hash,
// the encryption key/nonce, the share password, the hotlink (both the file's own field and the
// Hotlinks row), and the token (revoked, not merely orphaned) - while the grant itself and the
// file's name survive, because a disposed record is owner-visible history, not a wipe.
func TestDisposeClearsSecretsAndRevokesShareTokens(t *testing.T) {
	setRetention(t, "24h")
	os.Unsetenv("GOKAPI_DISABLE_HOTLINKS")

	sha1 := writeBlob(t, "secret-blob")
	id := "disposesecrets_" + helper.GenerateRandomString(8)
	file := models.File{
		Id:          id,
		Name:        "secret.jpg",
		SHA1:        sha1,
		ContentType: "image/jpg",
		ExpireAt:    time.Now().Add(-time.Hour).Unix(),
	}
	// AddHotlink refuses a password-protected file, so the hotlink has to be registered before
	// the password (and the other secrets, which are irrelevant to it) are added to the struct.
	AddHotlink(&file)
	test.IsEqualBool(t, file.HotlinkId != "", true)
	hotlinkId := file.HotlinkId
	file.PasswordHash = "somehash"
	file.EncryptedSharePassword = []byte("encrypted-share-password")
	file.Encryption = models.EncryptionInfo{
		IsEncrypted:   true,
		DecryptionKey: []byte("key"),
		Nonce:         []byte("nonce"),
	}
	database.SaveMetaData(file)

	recipientId := database.SaveShareRecipient(models.ShareRecipient{
		Email:     "disposal-test-" + id + "@example.com",
		CreatedAt: time.Now().Unix(),
	})
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceFile, id)
		database.DeleteShareRecipient(recipientId)
	})
	database.SetShareGrants(models.ShareResourceFile, id, []int{recipientId}, 999, 0)
	tokenHash := "disposal-test-token-" + id
	database.SaveShareLoginToken(models.ShareLoginToken{
		TokenHash:    tokenHash,
		RecipientId:  recipientId,
		ResourceType: models.ShareResourceFile,
		ResourceId:   id,
		CreatedAt:    time.Now().Unix(),
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
	})

	CleanUp(false)

	stored, ok := database.GetMetaDataById(id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, stored.IsDisposed(), true)
	test.IsEqualString(t, stored.SHA1, "")
	test.IsEqualString(t, stored.PasswordHash, "")
	test.IsEqualInt(t, len(stored.EncryptedSharePassword), 0)
	test.IsEqualInt(t, len(stored.Encryption.DecryptionKey), 0)
	test.IsEqualInt(t, len(stored.Encryption.Nonce), 0)
	test.IsEqualString(t, stored.HotlinkId, "")
	// Owner-visible history, not a wipe: the name is untouched by disposal.
	test.IsEqualString(t, stored.Name, "secret.jpg")

	_, hotlinkFound := database.GetHotlink(hotlinkId)
	test.IsEqualBool(t, hotlinkFound, false)

	grants := database.GetShareGrants(models.ShareResourceFile, id)
	test.IsEqualInt(t, len(grants), 1)

	token, tokenFound := database.GetShareLoginToken(tokenHash)
	test.IsEqualBool(t, tokenFound, true)
	test.IsEqualBool(t, token.IsRevoked, true)
}

// --- NameEncryptedRaw survives disposal while sealed ---

// TestDisposePreservesEncryptedFileNameWhileSealed is the data-loss regression guard the task
// calls out by name: this exact bug (a save-back path re-encrypting an empty Name while sealed,
// blanking the stored name) has been fixed twice before, and disposeFile writes every disposed
// row back through the same SaveMetaData path. This drives a real disposal - disposeFile itself,
// the exact function CleanUp calls for every row it disposes of, not a hand-simulated
// approximation of it - while the instance is genuinely sealed: a different salt than the one the
// real cipher was derived from, so IsDecryptionAvailable() is really false, not just "the key
// happens to be unset in this call". disposeFile is called directly rather than through
// CleanUp(false) because that sweeps every row in the shared test database, including fixture
// rows saved under a different, plaintext encryption regime by earlier tests - forcing the whole
// instance sealed here would make CleanUp try to re-encrypt those unrelated rows' names too and
// panic on a scenario that cannot occur in production (a single instance's encryption level does
// not change out from under a row the way switching it mid-test here would). Reads the row back
// after re-unsealing with the real cipher to prove the stored bytes, not merely the code path,
// survived.
func TestDisposePreservesEncryptedFileNameWhileSealed(t *testing.T) {
	previousLevel := configuration.Get().Encryption.Level
	defer func() {
		configuration.Get().Encryption.Level = previousLevel
		encryption.Init(models.Configuration{Encryption: models.Encryption{Level: encryption.NoEncryption}})
	}()

	cipher, err := encryption.GetRandomCipher()
	test.IsNil(t, err)
	configuration.Get().Encryption.Level = encryption.FullEncryptionStored
	encryption.Init(models.Configuration{Encryption: models.Encryption{
		Level: encryption.FullEncryptionStored, Cipher: cipher}})

	const secretName = "confidential-quarterly-report.xlsx"
	sha1 := writeBlob(t, "sealed-disposal-blob")
	id := "sealeddisposal_" + helper.GenerateRandomString(8)
	database.SaveMetaData(models.File{
		Id:                 id,
		Name:               secretName,
		SHA1:               sha1,
		ExpireAt:           time.Now().Add(-time.Hour).Unix(),
		UnlimitedDownloads: true,
	})

	// Confirm the name really was stored encrypted, not merely intended to be - otherwise this
	// test would prove nothing about the save-back path it exists to guard.
	rawFile, ok := database.GetMetaDataById(id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, rawFile.Name, secretName)
	test.IsEqualBool(t, len(rawFile.NameEncryptedRaw) > 0, true)

	// Seal for real: a different salt than the one the cipher above was derived from, exactly
	// like an instance freshly restarted and not yet unsealed by an administrator.
	configuration.Get().Encryption.Level = encryption.FullEncryptionInput
	encryption.Init(models.Configuration{Encryption: models.Encryption{
		Level: encryption.FullEncryptionInput, Salt: "sealed-disposal-salt",
		ChecksumSalt: "sealed-disposal-checksum-salt", Checksum: "irrelevant-while-sealed"}})
	test.IsEqualBool(t, encryption.IsSealed(), true)
	test.IsEqualBool(t, encryption.IsDecryptionAvailable(), false)

	// Read the row back exactly as CleanUp would (Name comes back "" - undecryptable while
	// sealed - but NameEncryptedRaw carries the original ciphertext regardless), then run the
	// real disposal function on it while genuinely unable to decrypt the name.
	sealedFile, ok := database.GetMetaDataById(id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, sealedFile.Name, "")
	test.IsEqualBool(t, len(sealedFile.NameEncryptedRaw) > 0, true)
	disposeFile(sealedFile, models.DisposalReasonExpired, "expired", time.Now().Unix(),
		configuration.Get().DataDir, map[string]int{sha1: 1})

	// Unseal with the real cipher again to read the result back.
	configuration.Get().Encryption.Level = encryption.FullEncryptionStored
	encryption.Init(models.Configuration{Encryption: models.Encryption{
		Level: encryption.FullEncryptionStored, Cipher: cipher}})

	stored, ok := database.GetMetaDataById(id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, stored.IsDisposed(), true)
	test.IsEqualString(t, stored.Name, secretName)
}

// --- cleanOrphanShareGrants: the sweep that removes a grant whose resource is gone ---

// TestCleanUpOrphanShareGrantsRemovesGrantForDeletedResource is the safety net for a crash
// between a resource delete and its cascade (database.DeleteFileBundle, DeleteFileRequest,
// DeleteMetaData all call DeleteShareGrants themselves, but nothing catches a process that dies
// between the two), and it is also the one-time backfill for grants that were orphaned before
// that cascade existed: a grant referencing a bundle that was never saved has no cascade that
// could ever have caught it, so only this sweep does. A grant on a bundle that genuinely exists
// must survive the very same sweep untouched.
func TestCleanUpOrphanShareGrantsRemovesGrantForDeletedResource(t *testing.T) {
	recipientId := database.SaveShareRecipient(models.ShareRecipient{
		Email:     "orphan-sweep-" + helper.GenerateRandomString(8) + "@example.com",
		CreatedAt: time.Now().Unix(),
	})
	t.Cleanup(func() { database.DeleteShareRecipient(recipientId) })

	orphanBundleId := "orphan_bundle_" + helper.GenerateRandomString(8)
	database.SetShareGrants(models.ShareResourceBundle, orphanBundleId, []int{recipientId}, 1, 0)

	// Control: a grant on a bundle that genuinely exists must not be touched by the same sweep.
	liveBundleId := "live_bundle_" + helper.GenerateRandomString(8)
	database.SaveFileBundle(models.FileBundle{
		Id:           liveBundleId,
		Name:         "orphan-sweep-live-bundle",
		CreationDate: time.Now().Unix(),
	})
	t.Cleanup(func() { database.DeleteFileBundle(models.FileBundle{Id: liveBundleId}) })
	database.SetShareGrants(models.ShareResourceBundle, liveBundleId, []int{recipientId}, 1, 0)

	CleanUp(false)

	test.IsEqualInt(t, len(database.GetShareGrants(models.ShareResourceBundle, orphanBundleId)), 0)
	test.IsEqualInt(t, len(database.GetShareGrants(models.ShareResourceBundle, liveBundleId)), 1)
}

// TestCleanUpKeepsGrantsForDisposedButNotPurgedFile is the case the orphan sweep must get
// right: a disposed file's metadata row is kept on purpose, as owner-visible history, until
// purgeFile removes it once the retention window elapses - and purgeFile is what deletes its
// grants, not the orphan sweep. GetMetaDataById returns a disposed row exactly like a live one,
// so shareResourceExists must (and does) treat it as still existing. Getting this wrong would
// delete a share's grants at dispose time, which is retention's whole point to prevent.
func TestCleanUpKeepsGrantsForDisposedButNotPurgedFile(t *testing.T) {
	setRetention(t, "24h")
	id := "disposed_not_purged_" + helper.GenerateRandomString(8)
	database.SaveMetaData(models.File{
		Id:             id,
		Name:           "disposed-not-purged.txt",
		DisposedAt:     time.Now().Add(-time.Minute).Unix(),
		DisposalReason: models.DisposalReasonExpired,
	})

	recipientId := database.SaveShareRecipient(models.ShareRecipient{
		Email:     "disposed-not-purged-" + id + "@example.com",
		CreatedAt: time.Now().Unix(),
	})
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceFile, id)
		database.DeleteShareRecipient(recipientId)
	})
	database.SetShareGrants(models.ShareResourceFile, id, []int{recipientId}, 999, 0)

	CleanUp(false)

	stored, ok := database.GetMetaDataById(id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, stored.IsDisposed(), true)

	grants := database.GetShareGrants(models.ShareResourceFile, id)
	test.IsEqualInt(t, len(grants), 1)
}

// --- CleanUpExpiredShareLoginTokens: was never called by anything before this ---

// TestCleanUpRunsExpiredShareLoginTokenSweep proves storage.CleanUp actually calls
// database.CleanUpExpiredShareLoginTokens, which previously had no caller anywhere in the
// codebase: a token whose ExpiresAt is already in the past must be gone after CleanUp runs, not
// merely after some other code path that never existed.
func TestCleanUpRunsExpiredShareLoginTokenSweep(t *testing.T) {
	tokenHash := "expired-sweep-token-" + helper.GenerateRandomString(8)
	database.SaveShareLoginToken(models.ShareLoginToken{
		TokenHash:    tokenHash,
		RecipientId:  1,
		ResourceType: models.ShareResourceFile,
		ResourceId:   "expired-sweep-resource",
		CreatedAt:    time.Now().Add(-time.Hour).Unix(),
		ExpiresAt:    time.Now().Add(-time.Minute).Unix(),
	})

	_, ok := database.GetShareLoginToken(tokenHash)
	test.IsEqualBool(t, ok, true)

	CleanUp(false)

	_, ok = database.GetShareLoginToken(tokenHash)
	test.IsEqualBool(t, ok, false)
}
