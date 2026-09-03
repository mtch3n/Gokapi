package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/shareaccess"
	"github.com/forceu/gokapi/internal/storage/filerequest"
	"github.com/forceu/gokapi/internal/test"
)

// This file covers the upload side of a file request restricted to named recipients.
//
// The entry endpoint (webserver.pubApiUploadRequest) already refuses a caller who is not a
// recipient, but it hands everyone it lets past the file request's own api key, and the chunk
// endpoints used to authorise on that key alone (checkFileRequestAndApiKey). A recipient who
// opened the upload page once therefore kept a working upload credential after the owner removed
// them from the list - revocation was immediate for downloads and did not exist for uploads.
// checkFileRequestAndApiKey now asks shareaccess.RecipientFor for the caller's current
// entitlement whenever the request is restricted, which is the same resolution and the same
// database.HasShareGrant predicate the download paths use.

// uploadGateAccessCookie mints the access cookie a recipient's browser carries after the public
// upload page exchanged their mailed token (shareaccess.RecipientFor -> WriteCookie), so a test
// can act as an already-authorised recipient without a mail round trip.
func uploadGateAccessCookie(resourceId string, recipientId int) test.Cookie {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/r/"+resourceId, nil)
	shareaccess.WriteCookie(recorder, request, models.ShareResourceFileRequest, resourceId, recipientId)
	cookies := recorder.Result().Cookies()
	return test.Cookie{Name: cookies[0].Name, Value: cookies[0].Value}
}

// uploadGateTokenHash hashes a raw token the same way shareaccess.hashToken does, so a test can
// plant a login token directly in the database. hashToken is unexported, so the hashing is
// duplicated here rather than exposed just for tests - the same approach
// Webserver_test.uploadRequestShareLoginTokenHash takes.
func uploadGateTokenHash(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}

// uploadGateShareToken plants a valid access token for a recipient and returns the raw value,
// which a caller presents in the sharetoken header the same way the SPA forwards the token it
// read out of the mailed link's fragment.
func uploadGateShareToken(t *testing.T, resourceId string, recipientId int) string {
	t.Helper()
	rawToken := "upload-gate-token-" + resourceId
	database.SaveShareLoginToken(models.ShareLoginToken{
		TokenHash:    uploadGateTokenHash(rawToken),
		RecipientId:  recipientId,
		ResourceType: models.ShareResourceFileRequest,
		ResourceId:   resourceId,
		CreatedAt:    time.Now().Unix(),
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
	})
	return rawToken
}

// uploadGateReserve calls /uploadrequest/chunk/reserve with the file request's api key plus
// whatever identity the caller carries, if any.
func uploadGateReserve(frId, apiKey string, cookies []test.Cookie, headers []test.Header) *httptest.ResponseRecorder {
	allHeaders := []test.Header{{Name: "apikey", Value: apiKey}, {Name: "id", Value: frId}}
	allHeaders = append(allHeaders, headers...)
	w, r := test.GetRecorder("POST", "/uploadrequest/chunk/reserve", cookies, allHeaders, nil)
	Process(w, r)
	return w
}

// uploadGateReservedUuid reads the reserved uuid out of a successful reservation.
func uploadGateReservedUuid(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var reserved struct {
		Uuid string
	}
	test.IsNil(t, json.Unmarshal(w.Body.Bytes(), &reserved))
	return reserved.Uuid
}

// uploadGateAdd calls /uploadrequest/chunk/add with a nine byte chunk, the same shape
// uploadChunkToFileRequest sends.
func uploadGateAdd(t *testing.T, frId, apiKey, uuid, tmpName string, cookies []test.Cookie, headers []test.Header) *httptest.ResponseRecorder {
	t.Helper()
	err := os.WriteFile("test/"+tmpName, []byte("gatetest1"), 0600)
	test.IsNil(t, err)
	body, formcontent := test.FileToMultipartFormBody(t, test.HttpTestConfig{
		UploadFileName:  "test/" + tmpName,
		UploadFieldName: "file",
		PostValues: []test.PostBody{{
			Key:   "filesize",
			Value: "9",
		}, {
			Key:   "offset",
			Value: "0",
		}, {
			Key:   "uuid",
			Value: uuid,
		}},
	})
	allHeaders := []test.Header{{Name: "apikey", Value: apiKey}, {Name: "fileRequestId", Value: frId}}
	allHeaders = append(allHeaders, headers...)
	w, r := test.GetRecorder("POST", "/uploadrequest/chunk/add", cookies, allHeaders, body)
	r.Header.Add("Content-Type", formcontent)
	Process(w, r)
	return w
}

// uploadGateComplete calls /uploadrequest/chunk/complete for a previously uploaded chunk.
func uploadGateComplete(frId, apiKey, uuid, fileName string, cookies []test.Cookie, headers []test.Header) *httptest.ResponseRecorder {
	allHeaders := []test.Header{
		{Name: "apikey", Value: apiKey},
		{Name: "uuid", Value: uuid},
		{Name: "filename", Value: fileName},
		{Name: "filesize", Value: "9"},
		{Name: "fileRequestId", Value: frId},
	}
	allHeaders = append(allHeaders, headers...)
	w, r := test.GetRecorder("POST", "/uploadrequest/chunk/complete", cookies, allHeaders, nil)
	Process(w, r)
	return w
}

// uploadGateNewRecipient creates a share recipient and removes it again after the test.
func uploadGateNewRecipient(t *testing.T, email string, isBlocked bool) int {
	t.Helper()
	recipientId := database.SaveShareRecipient(models.ShareRecipient{
		Email:     email,
		CreatedAt: time.Now().Unix(),
		IsBlocked: isBlocked,
	})
	t.Cleanup(func() {
		database.DeleteShareRecipient(recipientId)
	})
	return recipientId
}

// TestUploadGateRemovedRecipientCannotUpload is the headline case: a recipient who loaded the
// upload page once holds the file request's api key, and that key used to be the whole of the
// authorisation for /uploadrequest/chunk/*. Removing them from the recipient list - an ordinary
// edit in the share dialog, apiSetShareRecipients -> database.SetShareGrants - therefore revoked
// nothing on the upload side, and they could keep uploading for the life of the request.
//
// Nothing about the caller changes between the accepted reservation and the refused one: same
// api key, same cookie, same request. Only the recipient list is edited.
func TestUploadGateRemovedRecipientCannotUpload(t *testing.T) {
	frId, apiKey := newCappedFileRequest(t, "upload-gate-removed", 0)
	removedId := uploadGateNewRecipient(t, "upload-gate-removed@example.com", false)
	keptId := uploadGateNewRecipient(t, "upload-gate-kept@example.com", false)
	database.SetShareGrants(models.ShareResourceFileRequest, frId, []int{removedId, keptId}, idAdmin, 0)
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceFileRequest, frId)
	})
	cookie := uploadGateAccessCookie(frId, removedId)

	w := uploadGateReserve(frId, apiKey, []test.Cookie{cookie}, nil)
	test.IsEqualInt(t, w.Code, 200)
	uuid := uploadGateReservedUuid(t, w)

	// The owner edits the list and drops this recipient. The second recipient stays, so the
	// request is still restricted rather than falling back to being a public one.
	database.SetShareGrants(models.ShareResourceFileRequest, frId, []int{keptId}, idAdmin, 0)

	w = uploadGateReserve(frId, apiKey, []test.Cookie{cookie}, nil)
	test.IsEqualInt(t, w.Code, 404)

	w = uploadGateAdd(t, frId, apiKey, uuid, "upload-gate-removed-chunk", []test.Cookie{cookie}, nil)
	test.IsEqualInt(t, w.Code, 404)

	w = uploadGateComplete(frId, apiKey, uuid, "upload-gate-removed.upload", []test.Cookie{cookie}, nil)
	test.IsEqualInt(t, w.Code, 404)

	// Nothing reached the file request, so the removal really did revoke rather than only
	// change the answer of the last call.
	saved, ok := filerequest.Get(frId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, saved.UploadedFiles, 0)
	test.IsEqualInt(t, len(saved.Files), 0)
}

// TestUploadGateCurrentRecipientCanUploadWithCookie proves the gate does not lock out the person
// it exists to serve: a recipient still on the list uploads a whole file through reserve, add and
// complete carrying only the access cookie their browser was given.
func TestUploadGateCurrentRecipientCanUploadWithCookie(t *testing.T) {
	frId, apiKey := newCappedFileRequest(t, "upload-gate-cookie", 0)
	recipientId := uploadGateNewRecipient(t, "upload-gate-cookie@example.com", false)
	database.SetShareGrants(models.ShareResourceFileRequest, frId, []int{recipientId}, idAdmin, 0)
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceFileRequest, frId)
	})
	cookies := []test.Cookie{uploadGateAccessCookie(frId, recipientId)}

	// Control first: the same call without the cookie is refused, so the upload below proves the
	// cookie is what authorises rather than the api key on its own.
	control := uploadGateReserve(frId, apiKey, nil, nil)
	test.IsEqualInt(t, control.Code, 404)

	w := uploadGateReserve(frId, apiKey, cookies, nil)
	test.IsEqualInt(t, w.Code, 200)
	uuid := uploadGateReservedUuid(t, w)

	w = uploadGateAdd(t, frId, apiKey, uuid, "upload-gate-cookie-chunk", cookies, nil)
	test.IsEqualInt(t, w.Code, 200)

	w = uploadGateComplete(frId, apiKey, uuid, "upload-gate-cookie.upload", cookies, nil)
	test.IsEqualInt(t, w.Code, 200)

	// filerequest.Get rather than database.GetFileRequest: the file count is populated from the
	// metadata, not stored on the row.
	saved, ok := filerequest.Get(frId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, saved.UploadedFiles, 1)
	test.IsEqualInt(t, len(saved.Files), 1)
}

// TestUploadGateCurrentRecipientCanUploadWithToken is the same case reached the other way: a
// recipient who has no cookie yet, because they came straight from the mailed link, presents the
// raw token in the sharetoken header. Both credential routes have to work, exactly as they do
// for downloads, or a recipient uploading from a mailed link is locked out.
func TestUploadGateCurrentRecipientCanUploadWithToken(t *testing.T) {
	frId, apiKey := newCappedFileRequest(t, "upload-gate-token", 0)
	recipientId := uploadGateNewRecipient(t, "upload-gate-token@example.com", false)
	database.SetShareGrants(models.ShareResourceFileRequest, frId, []int{recipientId}, idAdmin, 0)
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceFileRequest, frId)
	})
	headers := []test.Header{{Name: "sharetoken", Value: uploadGateShareToken(t, frId, recipientId)}}

	// Control first, as above: without the token this caller is refused, so the upload below
	// proves the token is what authorises.
	control := uploadGateReserve(frId, apiKey, nil, nil)
	test.IsEqualInt(t, control.Code, 404)

	w := uploadGateReserve(frId, apiKey, nil, headers)
	test.IsEqualInt(t, w.Code, 200)
	uuid := uploadGateReservedUuid(t, w)

	w = uploadGateAdd(t, frId, apiKey, uuid, "upload-gate-token-chunk", nil, headers)
	test.IsEqualInt(t, w.Code, 200)

	w = uploadGateComplete(frId, apiKey, uuid, "upload-gate-token.upload", nil, headers)
	test.IsEqualInt(t, w.Code, 200)

	// filerequest.Get rather than database.GetFileRequest: the file count is populated from the
	// metadata, not stored on the row.
	saved, ok := filerequest.Get(frId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, saved.UploadedFiles, 1)
	test.IsEqualInt(t, len(saved.Files), 1)
}

// TestUploadGateUnrestrictedAcceptsAnonymousUpload is the regression guard. A file request with
// no recipient list is a public address: possession of the link, and therefore of the api key it
// hands out, is the whole of the authorisation. An anonymous guest with no cookie and no token
// must still be able to upload.
func TestUploadGateUnrestrictedAcceptsAnonymousUpload(t *testing.T) {
	frId, apiKey := newCappedFileRequest(t, "upload-gate-unrestricted", 0)

	w := uploadGateReserve(frId, apiKey, nil, nil)
	test.IsEqualInt(t, w.Code, 200)
	uuid := uploadGateReservedUuid(t, w)

	w = uploadGateAdd(t, frId, apiKey, uuid, "upload-gate-unrestricted-chunk", nil, nil)
	test.IsEqualInt(t, w.Code, 200)

	w = uploadGateComplete(frId, apiKey, uuid, "upload-gate-unrestricted.upload", nil, nil)
	test.IsEqualInt(t, w.Code, 200)

	// filerequest.Get rather than database.GetFileRequest: the file count is populated from the
	// metadata, not stored on the row.
	saved, ok := filerequest.Get(frId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, saved.UploadedFiles, 1)
	test.IsEqualInt(t, len(saved.Files), 1)
}

// TestUploadGateBlockedRecipientCannotUpload proves the gate means the same thing "may this
// recipient reach this resource" means everywhere else: database.HasShareGrant refuses a blocked
// recipient inside the query itself, so blocking one takes their uploads away without their grant
// row being touched. Blocking has no write path in the product today, so the flag is set directly,
// the same way TestApiShareInboxBlockedRecipientIsEmpty does.
func TestUploadGateBlockedRecipientCannotUpload(t *testing.T) {
	frId, apiKey := newCappedFileRequest(t, "upload-gate-blocked", 0)
	blockedId := uploadGateNewRecipient(t, "upload-gate-blocked@example.com", true)
	database.SetShareGrants(models.ShareResourceFileRequest, frId, []int{blockedId}, idAdmin, 0)
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceFileRequest, frId)
	})
	cookies := []test.Cookie{uploadGateAccessCookie(frId, blockedId)}

	w := uploadGateReserve(frId, apiKey, cookies, nil)
	test.IsEqualInt(t, w.Code, 404)

	w = uploadGateReserve(frId, apiKey, nil, []test.Header{
		{Name: "sharetoken", Value: uploadGateShareToken(t, frId, blockedId)},
	})
	test.IsEqualInt(t, w.Code, 404)
}

// TestUploadGateRefusalDoesNotRevealTheRequestExists checks the shape of the refusal rather than
// only its status: a caller refused for not being a recipient is answered exactly as a caller
// asking for a file request id that does not exist at all. Anything else would turn the upload
// endpoints into an oracle for which restricted request ids are real.
func TestUploadGateRefusalDoesNotRevealTheRequestExists(t *testing.T) {
	frId, apiKey := newCappedFileRequest(t, "upload-gate-refusal", 0)
	recipientId := uploadGateNewRecipient(t, "upload-gate-refusal@example.com", false)
	database.SetShareGrants(models.ShareResourceFileRequest, frId, []int{recipientId}, idAdmin, 0)
	t.Cleanup(func() {
		database.DeleteShareGrants(models.ShareResourceFileRequest, frId)
	})

	refused := uploadGateReserve(frId, apiKey, nil, nil)
	unknown := uploadGateReserve("upload-gate-no-such-request", apiKey, nil, nil)

	test.IsEqualInt(t, refused.Code, 404)
	test.IsEqualInt(t, unknown.Code, 404)
	test.IsEqualString(t, refused.Body.String(), unknown.Body.String())
	test.ResponseBodyIs(t, refused, `{"Result":"error","ErrorMessage":"FileRequest does not exist with the given ID","ErrorCode":5}`)
}
