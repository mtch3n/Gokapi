package applymaxexpiry

import (
	"os"
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/environment/flagparser"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/test"
	"github.com/forceu/gokapi/internal/test/testconfiguration"
)

func TestMain(m *testing.M) {
	testconfiguration.Create(false)
	// testconfiguration.Create leaves the database closed (it opens its own connection to seed
	// fixtures, then closes it) - reopen it the same way Do() itself does, so seedFiles below and
	// the assertions after each Do() call can use the database package directly. Do() reconnects
	// on every call, which is harmless against the same sqlite file.
	configuration.Load()
	configuration.ConnectDatabase()
	exitVal := m.Run()
	testconfiguration.Delete()
	os.Exit(exitVal)
}

var exitCode int

func setExitStub() {
	exitCode = 0
	osExit = func(code int) { exitCode = code }
}

const (
	idFarFuture       = "capfarfuture0000001"
	idUnlimited       = "capunlimited00000002"
	idWithinCap       = "capwithincap0000003"
	idPendingDeletion = "cappendingdel0000004"
)

const (
	reqFarFuture = "capreqfarfuture001"
	reqUnlimited = "capreqUnlimited002"
	reqWithinCap = "capreqwithincap003"
)

func seedFiles(t *testing.T) {
	now := time.Now().Unix()
	database.SaveMetaData(models.File{
		Id:       idFarFuture,
		Name:     "cap-test-far-future",
		Size:     "1 B",
		ExpireAt: now + int64((1000 * 24 * time.Hour).Seconds()),
	})
	database.SaveMetaData(models.File{
		Id:            idUnlimited,
		Name:          "cap-test-unlimited",
		Size:          "1 B",
		UnlimitedTime: true,
	})
	database.SaveMetaData(models.File{
		Id:       idWithinCap,
		Name:     "cap-test-within-cap",
		Size:     "1 B",
		ExpireAt: now + int64(time.Hour.Seconds()),
	})
	database.SaveMetaData(models.File{
		Id:              idPendingDeletion,
		Name:            "cap-test-pending-deletion",
		Size:            "1 B",
		UnlimitedTime:   true,
		PendingDeletion: now + int64(time.Hour.Seconds()),
	})

	// ApiKey is UNIQUE in the schema (it doubles as the request's public upload key) - each
	// fixture needs a distinct value, or INSERT OR REPLACE silently collapses them onto the
	// same row.
	database.SaveFileRequest(models.FileRequest{
		Id:     reqFarFuture,
		Name:   "cap-test-request-far-future",
		Expiry: now + int64((1000 * 24 * time.Hour).Seconds()),
		ApiKey: "capkey-far-future",
	})
	database.SaveFileRequest(models.FileRequest{
		Id:     reqUnlimited,
		Name:   "cap-test-request-unlimited",
		Expiry: 0,
		ApiKey: "capkey-unlimited",
	})
	database.SaveFileRequest(models.FileRequest{
		Id:     reqWithinCap,
		Name:   "cap-test-request-within-cap",
		Expiry: now + int64(time.Hour.Seconds()),
		ApiKey: "capkey-within-cap",
	})
}

func TestApplyMaxExpiry_RefusesWithoutMax(t *testing.T) {
	os.Unsetenv("GOKAPI_MAX_EXPIRY")
	setExitStub()
	seedFiles(t)

	Do(flagparser.ApplyMaxExpiryFlags{})
	test.IsEqualInt(t, exitCode, 1)

	// Nothing should have changed - the far-future file must still be unlimited-free-standing
	// as seeded.
	file, ok := database.GetMetaDataById(idFarFuture)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, file.UnlimitedTime, false)
}

func TestApplyMaxExpiry_DryRunChangesNothing(t *testing.T) {
	os.Setenv("GOKAPI_MAX_EXPIRY", "24h")
	defer os.Unsetenv("GOKAPI_MAX_EXPIRY")
	setExitStub()

	Do(flagparser.ApplyMaxExpiryFlags{DryRun: true})
	test.IsEqualInt(t, exitCode, 0)

	file, ok := database.GetMetaDataById(idFarFuture)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, file.UnlimitedTime, false)
	if file.ExpireAt < time.Now().Add(100*24*time.Hour).Unix() {
		t.Fatalf("dry run must not have changed ExpireAt, got %d", file.ExpireAt)
	}
	test.IsEqualString(t, file.Name, "cap-test-far-future")

	unlimited, ok := database.GetMetaDataById(idUnlimited)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, unlimited.UnlimitedTime, true)

	pending, ok := database.GetMetaDataById(idPendingDeletion)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, pending.UnlimitedTime, true)

	request, ok := database.GetFileRequest(reqFarFuture)
	test.IsEqualBool(t, ok, true)
	if request.Expiry < time.Now().Add(100*24*time.Hour).Unix() {
		t.Fatalf("dry run must not have changed request Expiry, got %d", request.Expiry)
	}
}

func TestApplyMaxExpiry_AppliesAndIsIdempotent(t *testing.T) {
	os.Setenv("GOKAPI_MAX_EXPIRY", "24h")
	defer os.Unsetenv("GOKAPI_MAX_EXPIRY")
	setExitStub()

	beforeCap := time.Now().Add(24 * time.Hour).Unix()
	Do(flagparser.ApplyMaxExpiryFlags{})
	afterCap := time.Now().Add(24 * time.Hour).Unix()
	test.IsEqualInt(t, exitCode, 0)

	// Far future file gets clamped to (approximately) now+24h, and loses UnlimitedTime
	file, ok := database.GetMetaDataById(idFarFuture)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, file.UnlimitedTime, false)
	if file.ExpireAt < beforeCap || file.ExpireAt > afterCap {
		t.Fatalf("expected ExpireAt clamped to ~%d, got %d", beforeCap, file.ExpireAt)
	}
	// The name must survive the save-back unchanged - the historical
	// NameEncryptedRaw-blanking bug this must not reintroduce.
	test.IsEqualString(t, file.Name, "cap-test-far-future")

	// Unlimited file gets a real expiry and loses UnlimitedTime
	unlimited, ok := database.GetMetaDataById(idUnlimited)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, unlimited.UnlimitedTime, false)
	if unlimited.ExpireAt < beforeCap || unlimited.ExpireAt > afterCap {
		t.Fatalf("expected ExpireAt clamped to ~%d, got %d", beforeCap, unlimited.ExpireAt)
	}

	// File already within the cap is left untouched
	within, ok := database.GetMetaDataById(idWithinCap)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, within.UnlimitedTime, false)
	if within.ExpireAt >= beforeCap {
		t.Fatalf("file within cap should have been left alone, got ExpireAt %d", within.ExpireAt)
	}

	// A file pending deletion matches neither condition and is left alone, even though it
	// carries UnlimitedTime=true
	pending, ok := database.GetMetaDataById(idPendingDeletion)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, pending.UnlimitedTime, true)

	// File requests: far future and unlimited both get clamped, name preserved
	reqFar, ok := database.GetFileRequest(reqFarFuture)
	test.IsEqualBool(t, ok, true)
	if reqFar.Expiry < beforeCap || reqFar.Expiry > afterCap {
		t.Fatalf("expected request Expiry clamped to ~%d, got %d", beforeCap, reqFar.Expiry)
	}
	test.IsEqualString(t, reqFar.Name, "cap-test-request-far-future")

	reqUnl, ok := database.GetFileRequest(reqUnlimited)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, reqUnl.IsUnlimitedTime(), false)
	if reqUnl.Expiry < beforeCap || reqUnl.Expiry > afterCap {
		t.Fatalf("expected request Expiry clamped to ~%d, got %d", beforeCap, reqUnl.Expiry)
	}

	reqWithin, ok := database.GetFileRequest(reqWithinCap)
	test.IsEqualBool(t, ok, true)
	if reqWithin.Expiry >= beforeCap {
		t.Fatalf("request within cap should have been left alone, got Expiry %d", reqWithin.Expiry)
	}

	// Second run: idempotent, nothing left to change
	fileBefore := file
	requestBefore := reqFar
	setExitStub()
	Do(flagparser.ApplyMaxExpiryFlags{})
	test.IsEqualInt(t, exitCode, 0)

	fileAfter, ok := database.GetMetaDataById(idFarFuture)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt64(t, fileAfter.ExpireAt, fileBefore.ExpireAt)
	test.IsEqualBool(t, fileAfter.UnlimitedTime, false)

	requestAfter, ok := database.GetFileRequest(reqFarFuture)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt64(t, requestAfter.Expiry, requestBefore.Expiry)
}
