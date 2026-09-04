//go:build !integration && test

package webserver

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/downloadsession"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/storage/filebundle"
	"github.com/forceu/gokapi/internal/test"
)

// eventFileDownload mirrors sse.eventFileDownload, which is unexported - the same shape
// Webserver_test.go's own local eventUploadStatus copy already uses for the same reason.
type eventFileDownload struct {
	Event              string `json:"event"`
	FileId             string `json:"file_id"`
	DownloadCount      int    `json:"download_count"`
	DownloadsRemaining int    `json:"downloads_remaining"`
}

// This file exercises the download-session protocol (POST /pubapi/downloadsession,
// POST /pubapi/foldersession, and the tokened legs of serveFile/pubApiFolderZip) through the
// real mux and a real client, the same way Webserver_test.go's other HTTP-level tests do.
//
// None of the tests below call t.Parallel(). setDownloadSessionLeeway mutates process-global
// environment state and reloads configuration.Get(), which every other test in this package -
// including every parallel one sharing the one webserver this package's TestMain starts - also
// reads. Go only ever runs the batch of t.Parallel() tests concurrently once every non-parallel
// top-level test has finished, so as long as nothing here calls t.Parallel() itself, this file's
// mutation window can never overlap one of theirs - see storage's identical setDownloadLeeway for
// the same reasoning, applied there because that package has no parallel tests to begin with.

// setDownloadSessionLeeway overrides GOKAPI_DOWNLOAD_SESSION_LEEWAY and
// GOKAPI_DOWNLOAD_SESSION_SIGN_KEY for the calling test, restoring the package's zero-leeway
// default once it finishes.
func setDownloadSessionLeeway(t *testing.T, value string) {
	t.Helper()
	os.Setenv("GOKAPI_DOWNLOAD_SESSION_LEEWAY", value)
	os.Setenv("GOKAPI_DOWNLOAD_SESSION_SIGN_KEY", "webserver_test_sign_key_at_least_32_characters_")
	configuration.Load()
	t.Cleanup(func() {
		os.Setenv("GOKAPI_DOWNLOAD_SESSION_LEEWAY", "0")
		os.Unsetenv("GOKAPI_DOWNLOAD_SESSION_SIGN_KEY")
		configuration.Load()
	})
}

// noRedirectClient is what every test below uses instead of http.DefaultClient: a caller
// following redirects cannot tell a 307 to /error apart from the page it points at, and D17 is
// specifically about that distinction never being reached on the tokened leg.
func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

// sessionResponse is the shape both new endpoints answer with.
type sessionResponse struct {
	Session          string `json:"session"`
	ExpiresAt        int64  `json:"expiresAt"`
	RequiresPassword bool   `json:"requiresPassword"`
}

// postDownloadSession POSTs /pubapi/downloadsession for fileId, carrying cookies if given, and
// decodes the JSON response. Fails the test outright on a transport error; a non-2xx status or a
// requiresPassword answer is left for the caller to assert on.
func postDownloadSession(t *testing.T, fileId string, cookies ...test.Cookie) (*http.Response, sessionResponse) {
	t.Helper()
	return postSession(t, "/pubapi/downloadsession?id="+fileId, cookies...)
}

// postFolderSession is postDownloadSession's folder twin.
func postFolderSession(t *testing.T, folderId string, cookies ...test.Cookie) (*http.Response, sessionResponse) {
	t.Helper()
	return postSession(t, "/pubapi/foldersession?id="+folderId, cookies...)
}

func postSession(t *testing.T, path string, cookies ...test.Cookie) (*http.Response, sessionResponse) {
	t.Helper()
	client := noRedirectClient()
	req, err := http.NewRequest(http.MethodPost, urlIp+path, nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	for _, c := range cookies {
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	var parsed sessionResponse
	_ = json.NewDecoder(resp.Body).Decode(&parsed)
	return resp, parsed
}

// newSessionTestFile creates a minimal unrestricted file backed by the "789" fixture blob
// (e017693e4a04a59d0b0f400fe98177fe7ee13cf7, written by testconfiguration.Create) and registers
// its cleanup.
func newSessionTestFile(t *testing.T, downloadsRemaining int, unlimited bool) models.File {
	t.Helper()
	file := models.File{
		Id:                 "sessionFile_" + helper.GenerateRandomString(12),
		Name:               "session_test.txt",
		Size:               "3 B",
		SizeBytes:          3,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ExpireAt:           2147483646,
		UnlimitedTime:      true,
		DownloadsRemaining: downloadsRemaining,
		UnlimitedDownloads: unlimited,
		ContentType:        "text/plain",
		UserId:             999,
	}
	database.SaveMetaData(file)
	t.Cleanup(func() { database.DeleteMetaData(file.Id) })
	return file
}

// newSessionTestBundle creates a folder with memberCount unrestricted members, all backed by the
// same fixture blob, and registers cleanup for both.
func newSessionTestBundle(t *testing.T, downloadsRemaining int, unlimited bool, memberCount int) (models.FileBundle, []models.File) {
	t.Helper()
	bundle := filebundle.Create("sessionBundle_"+helper.GenerateRandomString(8), 999)
	bundle.DownloadsRemaining = downloadsRemaining
	bundle.UnlimitedDownloads = unlimited
	database.SaveFileBundle(bundle)

	members := make([]models.File, 0, memberCount)
	for i := 0; i < memberCount; i++ {
		file := models.File{
			Id:                 "sessionMember_" + helper.GenerateRandomString(12),
			Name:               "member_" + helper.GenerateRandomString(4) + ".txt",
			Size:               "3 B",
			SizeBytes:          3,
			SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
			ExpireAt:           2147483646,
			UnlimitedDownloads: true,
			UnlimitedTime:      true,
			ContentType:        "text/plain",
			UserId:             999,
			BundleId:           bundle.Id,
		}
		database.SaveMetaData(file)
		members = append(members, file)
	}
	t.Cleanup(func() {
		for _, m := range members {
			database.DeleteMetaData(m.Id)
		}
		filebundle.Delete(bundle)
	})
	return bundle, members
}

// TestDownloadSessionPostSpendsAndReturnsToken covers the core mint: a one-download file's
// allowance is gone after the POST, a real token comes back, and a second POST on the
// now-spent-and-still-in-window file 404s - there is nothing left for it to mint from.
func TestDownloadSessionPostSpendsAndReturnsToken(t *testing.T) {
	setDownloadSessionLeeway(t, "5m")
	file := newSessionTestFile(t, 1, false)

	resp, parsed := postDownloadSession(t, file.Id)
	test.IsEqualInt(t, resp.StatusCode, http.StatusOK)
	if parsed.Session == "" {
		t.Fatalf("expected a session token, got none")
	}
	if parsed.ExpiresAt == 0 {
		t.Errorf("expected a nonzero expiresAt")
	}
	stored, ok := database.GetMetaDataById(file.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, stored.DownloadsRemaining, 0)

	resp2, parsed2 := postDownloadSession(t, file.Id)
	test.IsEqualInt(t, resp2.StatusCode, http.StatusNotFound)
	test.IsEqualString(t, parsed2.Session, "")
}

// TestDownloadSessionPostUnlimitedFileAnswersNoSession pins B1: an unlimited file has nothing to
// protect, so the endpoint must answer 200 with no session rather than 404.
func TestDownloadSessionPostUnlimitedFileAnswersNoSession(t *testing.T) {
	setDownloadSessionLeeway(t, "5m")
	file := newSessionTestFile(t, 0, true)

	resp, parsed := postDownloadSession(t, file.Id)
	test.IsEqualInt(t, resp.StatusCode, http.StatusOK)
	test.IsEqualString(t, parsed.Session, "")
	test.IsEqualInt64(t, parsed.ExpiresAt, 0)
}

// TestDownloadSessionPostPasscodeFileNoCookieAnswersRequiresPassword pins D29: a passcode file
// with no valid p<id> cookie answers requiresPassword, never 404 - the same shape a lapsed
// 5-minute cookie produces (isValidPwCookie draws no distinction between "never had one" and
// "had one, it expired").
func TestDownloadSessionPostPasscodeFileNoCookieAnswersRequiresPassword(t *testing.T) {
	setDownloadSessionLeeway(t, "5m")
	file := newSessionTestFile(t, 1, false)
	file.PasswordHash = configuration.HashPassword("session_test_password", false, "")
	database.SaveMetaData(file)

	resp, parsed := postDownloadSession(t, file.Id)
	test.IsEqualInt(t, resp.StatusCode, http.StatusOK)
	test.IsEqualBool(t, parsed.RequiresPassword, true)
	test.IsEqualString(t, parsed.Session, "")

	stored, ok := database.GetMetaDataById(file.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, stored.DownloadsRemaining, 1)
}

// TestTokenedGetServesAndSpendsNothingTwiceInARow is D6's core proof: the minted token can be
// used to fetch the same bytes twice, and neither request moves DownloadsRemaining - the pickup
// was already counted at the mint.
func TestTokenedGetServesAndSpendsNothingTwiceInARow(t *testing.T) {
	setDownloadSessionLeeway(t, "5m")
	file := newSessionTestFile(t, 1, false)

	_, parsed := postDownloadSession(t, file.Id)
	if parsed.Session == "" {
		t.Fatalf("expected a session token")
	}

	client := noRedirectClient()
	for i := 0; i < 2; i++ {
		resp, err := client.Get(urlIp + "/downloadFile?id=" + file.Id + "&session=" + parsed.Session)
		if err != nil {
			t.Fatalf("attempt %d: request failed: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		test.IsEqualInt(t, resp.StatusCode, http.StatusOK)
		test.IsEqualString(t, string(body), "789")
	}

	stored, ok := database.GetMetaDataById(file.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, stored.DownloadsRemaining, 0)
}

// TestSecondClickDoesNotSpendAndDoesNotRedirectToError is the regression this whole feature
// exists for: with revision 3's redirect design, a second click against a spent allowance fell
// through to the tokenless leg, which redirected to /error - an HTML page a browser configured
// to auto-download would save as the file. The SPA now holds the token from the mint, so its
// second click carries it and the file simply arrives again.
func TestSecondClickDoesNotSpendAndDoesNotRedirectToError(t *testing.T) {
	setDownloadSessionLeeway(t, "5m")
	file := newSessionTestFile(t, 1, false)

	_, parsed := postDownloadSession(t, file.Id)
	if parsed.Session == "" {
		t.Fatalf("expected a session token")
	}
	url := urlIp + "/downloadFile?id=" + file.Id + "&session=" + parsed.Session

	client := noRedirectClient()
	first, err := client.Get(url)
	if err != nil {
		t.Fatalf("first click failed: %v", err)
	}
	firstBody, _ := io.ReadAll(first.Body)
	first.Body.Close()
	test.IsEqualInt(t, first.StatusCode, http.StatusOK)
	test.IsEqualString(t, string(firstBody), "789")

	second, err := client.Get(url)
	if err != nil {
		t.Fatalf("second click failed: %v", err)
	}
	secondBody, _ := io.ReadAll(second.Body)
	second.Body.Close()
	test.IsEqualInt(t, second.StatusCode, http.StatusOK)
	test.IsEqualString(t, string(secondBody), "789")
	if second.Header.Get("Location") != "" {
		t.Errorf("second click redirected to %s instead of serving the file", second.Header.Get("Location"))
	}
}

// TestRefusedTokenedRequestAnswers404WithNoLocation pins D17: a session that does not verify
// (here, one minted for an id that no longer exists) gets a bare 404, never the redirect-to-
// /error the tokenless leg still uses - that redirect is what makes Chrome save error.html.
func TestRefusedTokenedRequestAnswers404WithNoLocation(t *testing.T) {
	setDownloadSessionLeeway(t, "5m")
	fakeId := "sessionFileMissing_" + helper.GenerateRandomString(12)
	token := downloadsession.Sign(models.ShareResourceFile, fakeId, 0, time.Now().Add(5*time.Minute).Unix())
	if token == "" {
		t.Fatalf("expected Sign to produce a token with a valid key")
	}

	client := noRedirectClient()
	resp, err := client.Get(urlIp + "/downloadFile?id=" + fakeId + "&session=" + token)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	test.IsEqualInt(t, resp.StatusCode, http.StatusNotFound)
	test.IsEqualString(t, resp.Header.Get("Location"), "")
}

// TestTamperedSessionDoesNotSpendOrFallThrough pins D10: a corrupted token is refused outright,
// never falling through to the tokenless leg - which, on a file with a real download left,
// would otherwise still spend it.
func TestTamperedSessionDoesNotSpendOrFallThrough(t *testing.T) {
	setDownloadSessionLeeway(t, "5m")
	file := newSessionTestFile(t, 2, false)

	_, parsed := postDownloadSession(t, file.Id)
	if parsed.Session == "" {
		t.Fatalf("expected a session token")
	}
	tampered := parsed.Session[:len(parsed.Session)-2] + "zz"

	client := noRedirectClient()
	resp, err := client.Get(urlIp + "/downloadFile?id=" + file.Id + "&session=" + tampered)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	test.IsEqualInt(t, resp.StatusCode, http.StatusNotFound)

	// Had the tampered token fallen through to the tokenless leg, this GET would have spent the
	// file's last remaining download instead of merely being refused.
	stored, ok := database.GetMetaDataById(file.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, stored.DownloadsRemaining, 1)
}

// TestHeadNeverSpendsFileTokenless pins D9 on the plain download door: a HEAD answers 200 and
// leaves DownloadsRemaining untouched.
func TestHeadNeverSpendsFileTokenless(t *testing.T) {
	file := newSessionTestFile(t, 1, false)

	client := noRedirectClient()
	req, err := http.NewRequest(http.MethodHead, urlIp+"/downloadFile?id="+file.Id, nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	test.IsEqualInt(t, resp.StatusCode, http.StatusOK)

	stored, ok := database.GetMetaDataById(file.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, stored.DownloadsRemaining, 1)
}

// TestHeadNeverSpendsFileTokened is the tokened twin: a HEAD against a session-backed URL
// answers 200 and does not consume the window - a real GET straight after it still works.
func TestHeadNeverSpendsFileTokened(t *testing.T) {
	setDownloadSessionLeeway(t, "5m")
	file := newSessionTestFile(t, 1, false)
	_, parsed := postDownloadSession(t, file.Id)
	if parsed.Session == "" {
		t.Fatalf("expected a session token")
	}
	url := urlIp + "/downloadFile?id=" + file.Id + "&session=" + parsed.Session

	client := noRedirectClient()
	headReq, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	headResp, err := client.Do(headReq)
	if err != nil {
		t.Fatalf("HEAD request failed: %v", err)
	}
	headResp.Body.Close()
	test.IsEqualInt(t, headResp.StatusCode, http.StatusOK)

	getResp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET request failed: %v", err)
	}
	defer getResp.Body.Close()
	test.IsEqualInt(t, getResp.StatusCode, http.StatusOK)
}

// TestHeadNeverSpendsFolderTokenless is TestHeadNeverSpendsFileTokenless's folder twin (D20).
func TestHeadNeverSpendsFolderTokenless(t *testing.T) {
	bundle, _ := newSessionTestBundle(t, 1, false, 2)

	client := noRedirectClient()
	req, err := http.NewRequest(http.MethodHead, urlIp+"/pubapi/folderzip?id="+bundle.Id, nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	test.IsEqualInt(t, resp.StatusCode, http.StatusOK)

	stored, ok := database.GetFileBundle(bundle.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, stored.DownloadsRemaining, 1)
}

// TestHeadNeverSpendsFolderTokened is the tokened folder twin.
func TestHeadNeverSpendsFolderTokened(t *testing.T) {
	setDownloadSessionLeeway(t, "5m")
	bundle, _ := newSessionTestBundle(t, 1, false, 2)
	_, parsed := postFolderSession(t, bundle.Id)
	if parsed.Session == "" {
		t.Fatalf("expected a session token")
	}

	client := noRedirectClient()
	req, err := http.NewRequest(http.MethodHead, urlIp+"/pubapi/folderzip?id="+bundle.Id+"&session="+parsed.Session, nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	test.IsEqualInt(t, resp.StatusCode, http.StatusOK)
}

// TestHeadOnRestrictedFileRevealsNothing pins B2: a HEAD against a recipient-restricted file,
// with no cookie proving the caller is that recipient, must not leak the file's name/size
// through Content-Disposition - the whole reason the non-spending authorisation check runs
// before the HEAD short-circuit rather than after.
func TestHeadOnRestrictedFileRevealsNothing(t *testing.T) {
	file := newSessionTestFile(t, 3, false)
	recipientId := database.SaveShareRecipient(models.ShareRecipient{
		Email: "head-restricted@example.com", CreatedAt: time.Now().Unix(),
	})
	database.SetShareGrants(models.ShareResourceFile, file.Id, []int{recipientId}, 999, 1)
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceFile, file.Id)
		database.DeleteShareRecipient(recipientId)
	})

	client := noRedirectClient()
	req, err := http.NewRequest(http.MethodHead, urlIp+"/downloadFile?id="+file.Id, nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Errorf("expected an unauthorised HEAD to be refused, got 200")
	}
	test.IsEqualString(t, resp.Header.Get("Content-Disposition"), "")
	test.IsEqualString(t, resp.Header.Get("Content-Length"), "")
}

// TestTokenedUrlWorksWithNoPasscodeCookie pins D8: once a token has been minted (which can only
// have happened after the passcode gate passed), the tokened GET works even from a client that
// presents no cookie at all - the requirement a copied URL in a cookie-less download manager
// depends on.
func TestTokenedUrlWorksWithNoPasscodeCookie(t *testing.T) {
	setDownloadSessionLeeway(t, "5m")
	file := newSessionTestFile(t, 1, false)
	file.PasswordHash = configuration.HashPassword("token_no_cookie_pw", false, "")
	database.SaveMetaData(file)

	cookie := testFilePasscodeCookie(t, file)
	_, parsed := postDownloadSession(t, file.Id, cookie)
	if parsed.Session == "" {
		t.Fatalf("expected a session token")
	}

	// No cookie at all on this request.
	client := noRedirectClient()
	resp, err := client.Get(urlIp + "/downloadFile?id=" + file.Id + "&session=" + parsed.Session)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	test.IsEqualInt(t, resp.StatusCode, http.StatusOK)
}

// TestFolderTokenMintedForOneSelectionServesDifferentSelectionFree pins D21: the folder token
// binds the bundle, not the ids requested at mint time, so a different selection is served free
// and the folder's own visit counter never moves again.
func TestFolderTokenMintedForOneSelectionServesDifferentSelectionFree(t *testing.T) {
	setDownloadSessionLeeway(t, "5m")
	bundle, members := newSessionTestBundle(t, 1, false, 2)

	_, parsed := postFolderSession(t, bundle.Id)
	if parsed.Session == "" {
		t.Fatalf("expected a session token")
	}

	client := noRedirectClient()
	resp1, err := client.Get(urlIp + "/pubapi/folderzip?id=" + bundle.Id + "&ids=" + members[0].Id + "&session=" + parsed.Session)
	if err != nil {
		t.Fatalf("first selection failed: %v", err)
	}
	resp1.Body.Close()
	test.IsEqualInt(t, resp1.StatusCode, http.StatusOK)

	resp2, err := client.Get(urlIp + "/pubapi/folderzip?id=" + bundle.Id + "&ids=" + members[1].Id + "&session=" + parsed.Session)
	if err != nil {
		t.Fatalf("second, different selection failed: %v", err)
	}
	resp2.Body.Close()
	test.IsEqualInt(t, resp2.StatusCode, http.StatusOK)

	stored, ok := database.GetFileBundle(bundle.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, stored.DownloadsRemaining, 0)
}

// TestTokenedMemberUrlRefused pins §6.2: a bundle member's OWN /downloadFile?id=<member> URL,
// presented with a folder-shaped session token, must be refused outright rather than silently
// downgraded into a tokenless folder request - the redirect at the top of serveFile has no way
// to carry the session parameter along with it.
func TestTokenedMemberUrlRefused(t *testing.T) {
	setDownloadSessionLeeway(t, "5m")
	bundle, members := newSessionTestBundle(t, 1, false, 1)
	_, parsed := postFolderSession(t, bundle.Id)
	if parsed.Session == "" {
		t.Fatalf("expected a session token")
	}

	client := noRedirectClient()
	resp, err := client.Get(urlIp + "/downloadFile?id=" + members[0].Id + "&session=" + parsed.Session)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	test.IsEqualInt(t, resp.StatusCode, http.StatusNotFound)
	test.IsEqualString(t, resp.Header.Get("Location"), "")
}

// TestPubApiFileIsNotFoundInWindowRegardlessOfSession pins D14: /pubapi/file is strict for
// everyone, with or without a session parameter riding along - the opener keeps their own page
// because the data is already in their browser's memory, not because the metadata endpoint made
// an exception for a session it does not even look at.
func TestPubApiFileIsNotFoundInWindowRegardlessOfSession(t *testing.T) {
	setDownloadSessionLeeway(t, "5m")
	file := newSessionTestFile(t, 1, false)
	_, parsed := postDownloadSession(t, file.Id)
	if parsed.Session == "" {
		t.Fatalf("expected a session token")
	}

	client := noRedirectClient()
	resp1, err := client.Get(urlIp + "/pubapi/file?id=" + file.Id)
	if err != nil {
		t.Fatalf("request without session failed: %v", err)
	}
	resp1.Body.Close()
	test.IsEqualInt(t, resp1.StatusCode, http.StatusNotFound)

	resp2, err := client.Get(urlIp + "/pubapi/file?id=" + file.Id + "&session=" + parsed.Session)
	if err != nil {
		t.Fatalf("request with session failed: %v", err)
	}
	resp2.Body.Close()
	test.IsEqualInt(t, resp2.StatusCode, http.StatusNotFound)
}

// TestTokenRecipientBlockedMidWindowRefused pins D23: blocking the recipient a token names
// after it was minted kills the token on the very next request, inside the same window.
func TestTokenRecipientBlockedMidWindowRefused(t *testing.T) {
	setDownloadSessionLeeway(t, "5m")
	file := newSessionTestFile(t, 3, false)
	recipientId := database.SaveShareRecipient(models.ShareRecipient{
		Email: "blocked-midwindow@example.com", CreatedAt: time.Now().Unix(),
	})
	database.SetShareGrants(models.ShareResourceFile, file.Id, []int{recipientId}, 999, 1)
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceFile, file.Id)
		database.DeleteShareRecipient(recipientId)
	})
	cookie := testShareAccessCookie(models.ShareResourceFile, file.Id, recipientId)

	_, parsed := postDownloadSession(t, file.Id, cookie)
	if parsed.Session == "" {
		t.Fatalf("expected a session token")
	}

	recipient, ok := database.GetShareRecipient(recipientId)
	test.IsEqualBool(t, ok, true)
	recipient.IsBlocked = true
	database.SaveShareRecipient(recipient)

	client := noRedirectClient()
	resp, err := client.Get(urlIp + "/downloadFile?id=" + file.Id + "&session=" + parsed.Session)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	test.IsEqualInt(t, resp.StatusCode, http.StatusNotFound)
}

// TestEightParallelPostsSpendExactlyOne proves the spend is atomic under contention: eight
// concurrent POSTs against a one-download file must mint exactly one token between them, not
// eight, and not zero.
func TestEightParallelPostsSpendExactlyOne(t *testing.T) {
	setDownloadSessionLeeway(t, "5m")
	file := newSessionTestFile(t, 1, false)

	const attempts = 8
	statusCodes := make([]int, attempts)
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			client := noRedirectClient()
			req, err := http.NewRequest(http.MethodPost, urlIp+"/pubapi/downloadsession?id="+file.Id, nil)
			if err != nil {
				t.Errorf("attempt %d: failed to build request: %v", idx, err)
				return
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Errorf("attempt %d: request failed: %v", idx, err)
				return
			}
			defer resp.Body.Close()
			statusCodes[idx] = resp.StatusCode
		}(i)
	}
	wg.Wait()

	successCount := 0
	for _, code := range statusCodes {
		if code == http.StatusOK {
			successCount++
		}
	}
	test.IsEqualInt(t, successCount, 1)

	stored, ok := database.GetMetaDataById(file.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, stored.DownloadsRemaining, 0)
}

// TestDownloadSessionPostRecipientGovernedFileMovesDownloadCountAndFiresSSE covers the branch
// added when Part 1's storage.GetFile/IsAvailableBundle strictness made the plan's §2.2
// assumption false: a recipient-governed file (SpendsOwnCounter == false) now DOES mint a
// token, because storage.GetFile no longer admits the spent-but-windowed aggregate for a
// tokenless retry. This is that branch's OWN half of storage.ServeFile's replicated spend - the
// file's DownloadCount and SSE event, which must not go silent just because the allowance
// actually spent belongs to a recipient's grant rather than the file's own row. Newest and least
// exercised code in this commit, so it gets its own dedicated proof rather than an inference from
// the plain-file case.
func TestDownloadSessionPostRecipientGovernedFileMovesDownloadCountAndFiresSSE(t *testing.T) {
	setDownloadSessionLeeway(t, "5m")
	file := models.File{
		Id:                 "sessionSseFile_" + helper.GenerateRandomString(12),
		Name:               "session_sse_test.txt",
		Size:               "3 B",
		SizeBytes:          3,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7",
		ExpireAt:           2147483646,
		UnlimitedTime:      true,
		DownloadsRemaining: 5,
		UnlimitedDownloads: false,
		ContentType:        "text/plain",
		// UserId 7 is who "session_token=validsession" (see testconfiguration.writeTestSessions)
		// authenticates as - the SSE listener below is filtered by this, exactly as
		// sse.publishMessage filters every event by file.UserId.
		UserId: 7,
	}
	database.SaveMetaData(file)
	t.Cleanup(func() { database.DeleteMetaData(file.Id) })

	recipientId := database.SaveShareRecipient(models.ShareRecipient{
		Email: "sse-recipient@example.com", CreatedAt: time.Now().Unix(),
	})
	database.SetShareGrants(models.ShareResourceFile, file.Id, []int{recipientId}, 7, 1)
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceFile, file.Id)
		database.DeleteShareRecipient(recipientId)
	})
	cookie := testShareAccessCookie(models.ShareResourceFile, file.Id, recipientId)

	before, ok := database.GetMetaDataById(file.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, before.DownloadCount, 0)

	// Open the SSE connection before triggering the spend, the same shape TestPostUpload already
	// uses for uploadStatus events.
	sseReq, err := http.NewRequest(http.MethodGet, urlIp+"/uploadStatus", nil)
	test.IsNil(t, err)
	sseReq.Header.Set("Accept", "text/event-stream")
	sseReq.Header.Set("Cookie", "session_token=validsession")
	sseResp, err := http.DefaultClient.Do(sseReq)
	test.IsNil(t, err)
	defer sseResp.Body.Close()
	test.IsEqualInt(t, sseResp.StatusCode, http.StatusOK)
	scanner := bufio.NewScanner(sseResp.Body)

	go func() {
		time.Sleep(200 * time.Millisecond)
		client := noRedirectClient()
		req, buildErr := http.NewRequest(http.MethodPost, urlIp+"/pubapi/downloadsession?id="+file.Id, nil)
		if buildErr != nil {
			t.Errorf("failed to build request: %v", buildErr)
			return
		}
		req.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
		resp, doErr := client.Do(req)
		if doErr != nil {
			t.Errorf("POST failed: %v", doErr)
			return
		}
		resp.Body.Close()
	}()

	var received eventFileDownload
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		message := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if jsonErr := json.Unmarshal([]byte(message), &received); jsonErr == nil && received.FileId == file.Id {
			break
		}
	}
	test.IsEqualString(t, received.FileId, file.Id)
	test.IsEqualInt(t, received.DownloadCount, 1)

	stored, ok := database.GetMetaDataById(file.Id)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, stored.DownloadCount, 1)
	// The recipient's own grant is what was spent - the file's own row, which SpendsOwnCounter
	// governs when this file has no grants, must stay untouched.
	test.IsEqualInt(t, stored.DownloadsRemaining, 5)
}

// TestFolderTokenRefusesMemberRemovedMidWindow pins D21's own justification for binding the
// token to the bundle rather than a frozen id list: membership is resolved fresh from the
// database on every request, tokened or not, so a member removed after the token was minted is
// refused rather than served from a stale snapshot the mint might otherwise have captured.
func TestFolderTokenRefusesMemberRemovedMidWindow(t *testing.T) {
	setDownloadSessionLeeway(t, "5m")
	bundle, members := newSessionTestBundle(t, 1, false, 2)

	_, parsed := postFolderSession(t, bundle.Id)
	if parsed.Session == "" {
		t.Fatalf("expected a session token")
	}

	// Remove the first member from the bundle after the token was minted - the same effect an
	// owner moving/deleting a member has.
	removed := members[0]
	removed.BundleId = ""
	database.SaveMetaData(removed)

	client := noRedirectClient()
	resp, err := client.Get(urlIp + "/pubapi/folderzip?id=" + bundle.Id + "&ids=" + members[0].Id + "&session=" + parsed.Session)
	if err != nil {
		t.Fatalf("request for the removed member failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Errorf("expected the removed member to be refused, got 200")
	}

	// The token is still good for the member that is still actually in the bundle.
	resp2, err := client.Get(urlIp + "/pubapi/folderzip?id=" + bundle.Id + "&ids=" + members[1].Id + "&session=" + parsed.Session)
	if err != nil {
		t.Fatalf("request for the live member failed: %v", err)
	}
	defer resp2.Body.Close()
	test.IsEqualInt(t, resp2.StatusCode, http.StatusOK)
}
