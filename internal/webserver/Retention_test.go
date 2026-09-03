//go:build !integration && test

package webserver

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/storage/filebundle"
	"github.com/forceu/gokapi/internal/test"
)

// This file holds the spine invariant of the metadata retention feature, stated by the owner:
// retention changes nothing a recipient can observe. A disposed record is owner-visible history
// and nothing else, and every public path must treat it exactly as it treats a record that was
// deleted outright. TestRetentionInvariant proves this by comparing two worlds per public path -
// one file deleted outright (no metadata row at all, reproducing pre-retention behaviour exactly),
// one identical file disposed of (DisposedAt set, row kept as history) - and asserting the public
// response is byte-for-byte identical: status, body, and headers.

// invariantResource carries every id a public-path request might need for one of the two worlds
// under comparison, captured at construction time since a "deleted outright" world has no
// metadata row left to look anything up from afterwards.
type invariantResource struct {
	FileId    string
	HotlinkId string
	BundleId  string
}

// buildInvariantResource sets up one of the two worlds TestRetentionInvariant compares. Both
// worlds start from the identical live file (image content type and an unrestricted hotlink, so
// every case in the table below has something to hit); "deleted outright" then removes the row
// (and its hotlink) entirely, reproducing the pre-retention behaviour of a completed deletion
// exactly, while "disposed" marks it via DisposedAt and leaves the row (but not the hotlink -
// disposeFile always removes it, see storage.disposeFile) behind as history.
//
// Neither path goes through storage.CleanUp or storage.DeleteFile: both operate on the entire
// database, and a test creating fixtures for a comparison like this one must not risk sweeping
// unrelated rows other parallel tests in this package depend on. Reaching the same end state
// directly is both safer and exactly as faithful, since the whole point of the comparison below
// is the public-path handlers' behaviour, not CleanUp's own bookkeeping (which the storage
// package's own tests already cover).
func buildInvariantResource(t *testing.T, label string, disposed bool) invariantResource {
	t.Helper()
	uniqueName := "RetentionInvariant_" + label + "_" + helper.GenerateRandomString(8)
	bundle := filebundle.Create(uniqueName, 999)
	fileId := helper.GenerateRandomString(16)
	hotlinkId := helper.GenerateRandomString(20) + ".jpg"

	file := models.File{
		Id:                 fileId,
		Name:               uniqueName + ".jpg",
		Size:               "3 B",
		SizeBytes:          3,
		SHA1:               "e017693e4a04a59d0b0f400fe98177fe7ee13cf7", // shared fixture blob, content "789"
		ContentType:        "image/jpg",
		ExpireAt:           2147483646,
		UnlimitedDownloads: true,
		UnlimitedTime:      true,
		UserId:             999,
		BundleId:           bundle.Id,
		HotlinkId:          hotlinkId,
	}

	if disposed {
		file.DisposedAt = time.Now().Add(-time.Minute).Unix()
		file.DisposalReason = models.DisposalReasonExpired
		file.HotlinkId = "" // disposeFile always clears this; see TestDisposeClearsSecretsAndRevokesShareTokens
		database.SaveMetaData(file)
		return invariantResource{FileId: fileId, HotlinkId: hotlinkId, BundleId: bundle.Id}
	}

	database.SaveMetaData(file)
	database.SaveHotlink(file)
	database.DeleteMetaData(fileId)
	database.DeleteHotlink(hotlinkId)
	return invariantResource{FileId: fileId, HotlinkId: hotlinkId, BundleId: bundle.Id}
}

// invariantRequest describes one HTTP request to issue against an invariantResource.
type invariantRequest struct {
	method      string
	url         func(invariantResource) string
	body        func(invariantResource) []byte
	contentType string
}

func (r invariantRequest) do(t *testing.T, res invariantResource) (int, string, http.Header) {
	t.Helper()
	var bodyReader io.Reader
	if r.body != nil {
		bodyReader = bytes.NewReader(r.body(res))
	}
	req, err := http.NewRequest(r.method, r.url(res), bodyReader)
	test.IsNil(t, err)
	if r.contentType != "" {
		req.Header.Set("Content-Type", r.contentType)
	}
	resp, err := (&http.Client{}).Do(req)
	test.IsNil(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	test.IsNil(t, err)
	headers := resp.Header.Clone()
	headers.Del("Date") // the one header expected to differ between two requests seconds apart
	return resp.StatusCode, string(body), headers
}

func shareResendBody(res invariantResource) []byte {
	payload, _ := json.Marshal(map[string]interface{}{
		"resourceType": models.ShareResourceFile,
		"resourceId":   res.FileId,
		"email":        "retention-invariant-" + res.FileId + "@example.com",
	})
	return payload
}

func filePasswordBody(invariantResource) []byte {
	payload, _ := json.Marshal(map[string]string{"password": "whatever-guess"})
	return payload
}

// TestRetentionInvariant is the parameterised comparison the task calls for, driving a table of
// public paths rather than one near-duplicate test per endpoint: the download route, hotlink (both
// the long and short URL forms), pubApiFileMetadata, pubApiFilePassword, the folder page, and
// pubApiShareResend.
func TestRetentionInvariant(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		req  invariantRequest
	}{
		{
			name: "download page",
			req: invariantRequest{method: "GET", url: func(r invariantResource) string {
				return urlIp + "/d?id=" + r.FileId
			}},
		},
		{
			name: "download action",
			req: invariantRequest{method: "GET", url: func(r invariantResource) string {
				return urlIp + "/downloadFile?id=" + r.FileId
			}},
		},
		{
			name: "hotlink long form",
			req: invariantRequest{method: "GET", url: func(r invariantResource) string {
				return urlIp + "/hotlink/" + r.HotlinkId
			}},
		},
		{
			name: "hotlink short form",
			req: invariantRequest{method: "GET", url: func(r invariantResource) string {
				return urlIp + "/h/" + r.HotlinkId
			}},
		},
		{
			name: "pubApiFileMetadata",
			req: invariantRequest{method: "GET", url: func(r invariantResource) string {
				return urlIp + "/pubapi/file?id=" + r.FileId
			}},
		},
		{
			name: "pubApiFilePassword",
			req: invariantRequest{method: "POST", url: func(r invariantResource) string {
				return urlIp + "/pubapi/filepassword?id=" + r.FileId
			}, body: filePasswordBody, contentType: "application/json"},
		},
		{
			name: "folder page",
			req: invariantRequest{method: "GET", url: func(r invariantResource) string {
				return urlIp + "/pubapi/folder?id=" + r.BundleId
			}},
		},
		{
			name: "pubApiShareResend",
			req: invariantRequest{method: "POST", url: func(invariantResource) string {
				return urlIp + "/pubapi/share/resend"
			}, body: shareResendBody, contentType: "application/json"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			deleted := buildInvariantResource(t, "deleted", false)
			disposed := buildInvariantResource(t, "disposed", true)

			statusDeleted, bodyDeleted, headersDeleted := tc.req.do(t, deleted)
			statusDisposed, bodyDisposed, headersDisposed := tc.req.do(t, disposed)

			if statusDeleted != statusDisposed {
				t.Errorf("%s: status code differs - deleted outright: %d, disposed: %d",
					tc.name, statusDeleted, statusDisposed)
			}
			if bodyDeleted != bodyDisposed {
				t.Errorf("%s: response body differs\n deleted outright: %q\n disposed:         %q",
					tc.name, bodyDeleted, bodyDisposed)
			}
			if len(headersDeleted) != len(headersDisposed) {
				t.Errorf("%s: header sets differ in size - deleted outright: %v, disposed: %v",
					tc.name, headersDeleted, headersDisposed)
			}
			for key, values := range headersDeleted {
				otherValues, ok := headersDisposed[key]
				if !ok || len(values) != len(otherValues) {
					t.Errorf("%s: header %q differs - deleted outright: %v, disposed: %v",
						tc.name, key, values, otherValues)
					continue
				}
				for i := range values {
					if values[i] != otherValues[i] {
						t.Errorf("%s: header %q differs - deleted outright: %v, disposed: %v",
							tc.name, key, values, otherValues)
					}
				}
			}
		})
	}
}

// TestRetentionInvariantShareResendMailsNothingEitherWay is pubApiShareResend's specific
// requirement beyond the uniform-response check above: since every outcome answers the same "OK"
// regardless of what happened (see pubApiShareResend's own doc comment), the response body alone
// cannot prove a disposed file is treated like a deleted one for this endpoint - only the absence
// of an actually-issued token can. Mirrors the pattern already established by
// TestPublicApiShareResendExpiredFileRequestMailsNothing.
func TestRetentionInvariantShareResendMailsNothingEitherWay(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		disposed bool
	}{
		{"deleted outright", false},
		{"disposed", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := buildInvariantResource(t, "resendmail", tc.disposed)

			recipientId := database.SaveShareRecipient(models.ShareRecipient{
				Email:     "retention-resend-" + res.FileId + "@example.com",
				CreatedAt: time.Now().Unix(),
			})
			t.Cleanup(func() {
				database.DeleteShareGrants(models.ShareResourceFile, res.FileId)
				database.DeleteShareRecipient(recipientId)
			})
			database.SetShareGrants(models.ShareResourceFile, res.FileId, []int{recipientId}, 999, 0)

			req := invariantRequest{method: "POST", url: func(invariantResource) string {
				return urlIp + "/pubapi/share/resend"
			}, body: func(invariantResource) []byte {
				payload, _ := json.Marshal(map[string]interface{}{
					"resourceType": models.ShareResourceFile,
					"resourceId":   res.FileId,
					"email":        "retention-resend-" + res.FileId + "@example.com",
				})
				return payload
			}, contentType: "application/json"}

			status, body, _ := req.do(t, res)
			test.IsEqualInt(t, status, http.StatusOK)
			test.IsEqualString(t, body, `{"result":"OK"}`)

			if lastIssued := database.GetLastShareLoginTokenTime(recipientId, models.ShareResourceFile, res.FileId); lastIssued != 0 {
				t.Errorf("expected no mail to be sent (no access token minted) for a %s file, but one was issued at %d", tc.name, lastIssued)
			}
		})
	}
}
