//go:build !integration && test

package webserver

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/shareaccess"
	"github.com/forceu/gokapi/internal/test"
)

// This file pins mayDownloadFile and mayDownloadBundle (ShareGuard.go) against the verdict
// today's spending gates reach - shareaccess.ConsumeDownload inline in serveFile and
// consumeShareDownload, both in Webserver.go - for every case the leeway-session-token plan's
// D27 lists, and proves each one spends nothing: neither the resource's own DownloadsRemaining
// nor a grant row's DownloadsUsed moves, no matter which way the call comes out.
//
// No leeway override is needed anywhere below: every scenario here turns on either no
// restriction at all, or a grant that is either fresh (DownloadsUsed 0) or fully spent
// (DownloadsUsed == DownloadsAllowed), and at the package's default leeway of 0 a spent grant's
// window closes the instant it opens - see models.DownloadAccess.IsExhausted - so "spent" and
// "exhausted" already coincide without touching GOKAPI_DOWNLOAD_LEEWAY.

// newGuardRequest builds a bare request against the running test server, carrying whichever
// cookies a case needs. mayDownloadFile and mayDownloadBundle read identity purely from cookies
// and headers, never from the URL path, so a fixed placeholder path is enough for every case.
func newGuardRequest(cookies ...test.Cookie) *http.Request {
	req := httptest.NewRequest(http.MethodGet, urlIp+"/", nil)
	for _, c := range cookies {
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	return req
}

// testFilePasscodeCookie mints a valid p<id> cookie for a file the same way writeFilePwCookie
// does for a caller who just typed the correct password, so a test can act as one without going
// through the password-submission endpoint.
func testFilePasscodeCookie(t *testing.T, file models.File) test.Cookie {
	t.Helper()
	recorder := httptest.NewRecorder()
	writeFilePwCookie(recorder, file)
	cookies := recorder.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("writeFilePwCookie set no cookie")
	}
	return test.Cookie{Name: cookies[0].Name, Value: cookies[0].Value}
}

// testBundlePasscodeCookie is testFilePasscodeCookie's folder twin.
func testBundlePasscodeCookie(t *testing.T, bundle models.FileBundle) test.Cookie {
	t.Helper()
	recorder := httptest.NewRecorder()
	writeFolderPwCookie(recorder, bundle)
	cookies := recorder.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("writeFolderPwCookie set no cookie")
	}
	return test.Cookie{Name: cookies[0].Name, Value: cookies[0].Value}
}

// grantDownloadsUsed reads one recipient's DownloadsUsed off the stored grant row directly,
// which is the ground truth mayDownloadFile/mayDownloadBundle must never move.
func grantDownloadsUsed(t *testing.T, resourceType int, resourceId string, recipientId int) int {
	t.Helper()
	for _, grant := range database.GetShareGrants(resourceType, resourceId) {
		if grant.RecipientId == recipientId {
			return grant.DownloadsUsed
		}
	}
	t.Fatalf("no grant found for recipient %d on resource type %d id %s", recipientId, resourceType, resourceId)
	return 0
}

func TestMayDownloadFileUnrestrictedPublicFile(t *testing.T) {
	t.Parallel()
	fileId := "guardPublicFile" + helper.GenerateRandomString(8)
	database.SaveMetaData(models.File{
		Id: fileId, Name: "public.txt", SHA1: "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		UserId: 999, UnlimitedTime: true, DownloadsRemaining: 3,
	})
	t.Cleanup(func() { database.DeleteMetaData(fileId) })

	before, ok := database.GetMetaDataById(fileId)
	test.IsEqualBool(t, ok, true)

	result := mayDownloadFile(httptest.NewRecorder(), newGuardRequest(), before)

	test.IsEqualBool(t, result.Authorised, true)
	test.IsEqualInt(t, result.RecipientId, 0)
	test.IsEqualBool(t, result.RequiresPassword, false)

	after, ok := database.GetMetaDataById(fileId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, after.DownloadsRemaining, before.DownloadsRemaining)
}

func TestMayDownloadFileRecipientRestrictedValidCookie(t *testing.T) {
	t.Parallel()
	fileId := "guardRecipValid" + helper.GenerateRandomString(8)
	database.SaveMetaData(models.File{
		Id: fileId, Name: "restricted.txt", SHA1: "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		UserId: 999, UnlimitedTime: true, DownloadsRemaining: 5,
	})
	recipientId := database.SaveShareRecipient(models.ShareRecipient{
		Email: "guard-valid-" + helper.GenerateRandomString(6) + "@example.com", CreatedAt: time.Now().Unix()})
	database.SetShareGrants(models.ShareResourceFile, fileId, []int{recipientId}, 999, 3)
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceFile, fileId)
		database.DeleteShareRecipient(recipientId)
		database.DeleteMetaData(fileId)
	})

	file, ok := database.GetMetaDataById(fileId)
	test.IsEqualBool(t, ok, true)
	cookie := testShareAccessCookie(models.ShareResourceFile, fileId, recipientId)

	fileBefore := file.DownloadsRemaining
	usedBefore := grantDownloadsUsed(t, models.ShareResourceFile, fileId, recipientId)

	result := mayDownloadFile(httptest.NewRecorder(), newGuardRequest(cookie), file)

	test.IsEqualBool(t, result.Authorised, true)
	test.IsEqualInt(t, result.RecipientId, recipientId)
	test.IsEqualBool(t, result.RequiresPassword, false)

	after, ok := database.GetMetaDataById(fileId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, after.DownloadsRemaining, fileBefore)
	test.IsEqualInt(t, grantDownloadsUsed(t, models.ShareResourceFile, fileId, recipientId), usedBefore)
}

func TestMayDownloadFileRecipientRestrictedNoCookie(t *testing.T) {
	t.Parallel()
	fileId := "guardRecipNoCookie" + helper.GenerateRandomString(8)
	database.SaveMetaData(models.File{
		Id: fileId, Name: "restricted.txt", SHA1: "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		UserId: 999, UnlimitedTime: true, DownloadsRemaining: 5,
	})
	recipientId := database.SaveShareRecipient(models.ShareRecipient{
		Email: "guard-nocookie-" + helper.GenerateRandomString(6) + "@example.com", CreatedAt: time.Now().Unix()})
	database.SetShareGrants(models.ShareResourceFile, fileId, []int{recipientId}, 999, 3)
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceFile, fileId)
		database.DeleteShareRecipient(recipientId)
		database.DeleteMetaData(fileId)
	})

	file, ok := database.GetMetaDataById(fileId)
	test.IsEqualBool(t, ok, true)

	usedBefore := grantDownloadsUsed(t, models.ShareResourceFile, fileId, recipientId)

	result := mayDownloadFile(httptest.NewRecorder(), newGuardRequest(), file)

	test.IsEqualBool(t, result.Authorised, false)
	test.IsEqualBool(t, result.RequiresPassword, false)

	after, ok := database.GetMetaDataById(fileId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, after.DownloadsRemaining, file.DownloadsRemaining)
	test.IsEqualInt(t, grantDownloadsUsed(t, models.ShareResourceFile, fileId, recipientId), usedBefore)
}

func TestMayDownloadFileRecipientBlocked(t *testing.T) {
	t.Parallel()
	fileId := "guardBlocked" + helper.GenerateRandomString(8)
	database.SaveMetaData(models.File{
		Id: fileId, Name: "blocked.txt", SHA1: "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		UserId: 999, UnlimitedTime: true, DownloadsRemaining: 4,
	})
	recipientId := database.SaveShareRecipient(models.ShareRecipient{
		Email: "guard-blocked-" + helper.GenerateRandomString(6) + "@example.com", CreatedAt: time.Now().Unix()})
	database.SetShareGrants(models.ShareResourceFile, fileId, []int{recipientId}, 999, 3)
	// The cookie is minted before the recipient is blocked, exactly as a real cookie would
	// already be sitting in a browser at the moment staff blocks the address - the refusal has
	// to come from the live HasShareGrant re-check inside shareaccess.RecipientFor, not from the
	// cookie itself somehow knowing.
	cookie := testShareAccessCookie(models.ShareResourceFile, fileId, recipientId)

	recipient, ok := database.GetShareRecipient(recipientId)
	test.IsEqualBool(t, ok, true)
	recipient.IsBlocked = true
	database.SaveShareRecipient(recipient)

	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceFile, fileId)
		database.DeleteShareRecipient(recipientId)
		database.DeleteMetaData(fileId)
	})

	file, ok := database.GetMetaDataById(fileId)
	test.IsEqualBool(t, ok, true)
	usedBefore := grantDownloadsUsed(t, models.ShareResourceFile, fileId, recipientId)

	result := mayDownloadFile(httptest.NewRecorder(), newGuardRequest(cookie), file)

	test.IsEqualBool(t, result.Authorised, false)

	after, ok := database.GetMetaDataById(fileId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, after.DownloadsRemaining, file.DownloadsRemaining)
	test.IsEqualInt(t, grantDownloadsUsed(t, models.ShareResourceFile, fileId, recipientId), usedBefore)
}

func TestMayDownloadFileRecipientAllowanceExhausted(t *testing.T) {
	t.Parallel()
	fileId := "guardExhausted" + helper.GenerateRandomString(8)
	database.SaveMetaData(models.File{
		Id: fileId, Name: "exhausted.txt", SHA1: "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		UserId: 999, UnlimitedTime: true, DownloadsRemaining: 4,
	})
	recipientId := database.SaveShareRecipient(models.ShareRecipient{
		Email: "guard-exhausted-" + helper.GenerateRandomString(6) + "@example.com", CreatedAt: time.Now().Unix()})
	database.SetShareGrants(models.ShareResourceFile, fileId, []int{recipientId}, 999, 1)
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceFile, fileId)
		database.DeleteShareRecipient(recipientId)
		database.DeleteMetaData(fileId)
	})

	// Spend the recipient's one download for real, through the same shareaccess.ConsumeDownload
	// the live spend path uses, so the fixture is a genuinely exhausted grant rather than one
	// merely configured to look like it. This is fixture setup, not the thing under test.
	err := shareaccess.ConsumeDownload(models.ShareResourceFile, fileId, recipientId, 0)
	test.IsNil(t, err)

	cookie := testShareAccessCookie(models.ShareResourceFile, fileId, recipientId)
	file, ok := database.GetMetaDataById(fileId)
	test.IsEqualBool(t, ok, true)
	usedBefore := grantDownloadsUsed(t, models.ShareResourceFile, fileId, recipientId)
	test.IsEqualInt(t, usedBefore, 1)

	result := mayDownloadFile(httptest.NewRecorder(), newGuardRequest(cookie), file)

	// The point of this test: refused HERE, before any spend is attempted, not merely at the
	// eventual spend call.
	test.IsEqualBool(t, result.Authorised, false)

	after, ok := database.GetMetaDataById(fileId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, after.DownloadsRemaining, file.DownloadsRemaining)
	test.IsEqualInt(t, grantDownloadsUsed(t, models.ShareResourceFile, fileId, recipientId), usedBefore)
}

func TestMayDownloadFilePasscode(t *testing.T) {
	t.Parallel()
	fileId := "guardPasscode" + helper.GenerateRandomString(8)
	database.SaveMetaData(models.File{
		Id: fileId, Name: "secret.txt", SHA1: "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		UserId: 999, UnlimitedTime: true, DownloadsRemaining: 2, PasswordHash: "$2a$10$notarealhash",
	})
	t.Cleanup(func() { database.DeleteMetaData(fileId) })

	file, ok := database.GetMetaDataById(fileId)
	test.IsEqualBool(t, ok, true)
	before := file.DownloadsRemaining

	// Without the cookie: refused, and specifically because a password is needed - not "not
	// found" and not any other reason, so a caller downstream can tell the two apart.
	withoutCookie := mayDownloadFile(httptest.NewRecorder(), newGuardRequest(), file)
	test.IsEqualBool(t, withoutCookie.Authorised, false)
	test.IsEqualBool(t, withoutCookie.RequiresPassword, true)

	// With a valid p<id> cookie: authorised.
	cookie := testFilePasscodeCookie(t, file)
	withCookie := mayDownloadFile(httptest.NewRecorder(), newGuardRequest(cookie), file)
	test.IsEqualBool(t, withCookie.Authorised, true)
	test.IsEqualBool(t, withCookie.RequiresPassword, false)

	after, ok := database.GetMetaDataById(fileId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, after.DownloadsRemaining, before)
}

func TestMayDownloadBundlePassword(t *testing.T) {
	t.Parallel()
	bundleId := "guardPwBundle" + helper.GenerateRandomString(8)
	bundle := models.FileBundle{
		Id: bundleId, Name: "pw folder", UserId: 999, CreationDate: time.Now().Unix(),
		DownloadsRemaining: 2, UnlimitedTime: true, PasswordHash: "$2a$10$notarealhash",
	}
	database.SaveFileBundle(bundle)
	t.Cleanup(func() { database.DeleteFileBundle(bundle) })

	stored, ok := database.GetFileBundle(bundleId)
	test.IsEqualBool(t, ok, true)
	before := stored.DownloadsRemaining

	withoutCookie := mayDownloadBundle(httptest.NewRecorder(), newGuardRequest(), stored)
	test.IsEqualBool(t, withoutCookie.Authorised, false)
	test.IsEqualBool(t, withoutCookie.RequiresPassword, true)

	cookie := testBundlePasscodeCookie(t, stored)
	withCookie := mayDownloadBundle(httptest.NewRecorder(), newGuardRequest(cookie), stored)
	test.IsEqualBool(t, withCookie.Authorised, true)
	test.IsEqualBool(t, withCookie.RequiresPassword, false)

	after, ok := database.GetFileBundle(bundleId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, after.DownloadsRemaining, before)
}

func TestMayDownloadFileBundleGovernedMember(t *testing.T) {
	t.Parallel()
	bundleId := "guardMemberBundle" + helper.GenerateRandomString(8)
	database.SaveFileBundle(models.FileBundle{
		Id: bundleId, Name: "member folder", UserId: 999, CreationDate: time.Now().Unix(),
		DownloadsRemaining: 2, UnlimitedTime: true,
	})
	memberId := helper.GenerateRandomString(16)
	database.SaveMetaData(models.File{
		Id: memberId, Name: "member.txt", SHA1: "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		UserId: 999, BundleId: bundleId, ExpireAt: 2147483646,
	})
	recipientId := database.SaveShareRecipient(models.ShareRecipient{
		Email: "guard-member-" + helper.GenerateRandomString(6) + "@example.com", CreatedAt: time.Now().Unix()})
	database.SetShareGrants(models.ShareResourceBundle, bundleId, []int{recipientId}, 999, 3)
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceBundle, bundleId)
		database.DeleteShareRecipient(recipientId)
		database.DeleteMetaData(memberId)
		database.DeleteFileBundle(models.FileBundle{Id: bundleId})
	})

	file, ok := database.GetMetaDataById(memberId)
	test.IsEqualBool(t, ok, true)
	bundleBefore, ok := database.GetFileBundle(bundleId)
	test.IsEqualBool(t, ok, true)
	usedBefore := grantDownloadsUsed(t, models.ShareResourceBundle, bundleId, recipientId)

	// No cookie: the member carries no restriction of its own, but its governing bundle does,
	// and that is refused exactly as serveFile's bundle cascade refuses it.
	withoutCookie := mayDownloadFile(httptest.NewRecorder(), newGuardRequest(), file)
	test.IsEqualBool(t, withoutCookie.Authorised, false)

	cookie := testShareAccessCookie(models.ShareResourceBundle, bundleId, recipientId)
	withCookie := mayDownloadFile(httptest.NewRecorder(), newGuardRequest(cookie), file)
	test.IsEqualBool(t, withCookie.Authorised, true)
	test.IsEqualInt(t, withCookie.RecipientId, recipientId)

	fileAfter, ok := database.GetMetaDataById(memberId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, fileAfter.DownloadsRemaining, file.DownloadsRemaining)
	bundleAfter, ok := database.GetFileBundle(bundleId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, bundleAfter.DownloadsRemaining, bundleBefore.DownloadsRemaining)
	test.IsEqualInt(t, grantDownloadsUsed(t, models.ShareResourceBundle, bundleId, recipientId), usedBefore)
}
