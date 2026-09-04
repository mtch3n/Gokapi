package headers

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/test"
)

func TestWriteDownloadHeaders(t *testing.T) {

	// --- ASCII filename, force download ---
	file := models.File{Name: "testname.zip", ContentType: "application/zip", SizeBytes: 1234}
	w, _ := test.GetRecorder("GET", "/test", nil, nil, nil)
	Write(file, w, true, false)
	test.IsEqualString(t, w.Result().Header.Get("Content-Disposition"), "attachment; filename=\"testname.zip\"; filename*=UTF-8''testname.zip")
	test.IsEqualString(t, w.Result().Header.Get("Content-Security-Policy"), "") // must NOT be set for downloads
	test.IsEqualString(t, w.Result().Header.Get("Content-Type"), "application/zip")
	test.IsEqualString(t, w.Result().Header.Get("Content-Length"), "1234")

	// --- ASCII filename, inline ---
	w, _ = test.GetRecorder("GET", "/test", nil, nil, nil)
	Write(file, w, false, false)
	test.IsEqualString(t, w.Result().Header.Get("Content-Disposition"), "inline; filename=\"testname.zip\"; filename*=UTF-8''testname.zip")
	test.IsEqualString(t, w.Result().Header.Get("Content-Security-Policy"), "sandbox")
	test.IsEqualString(t, w.Result().Header.Get("Content-Type"), "application/zip")

	// --- UTF-8 filename with spaces, Cyrillic, and parentheses ---
	file.Name = "тест файл (3).zip"
	w, _ = test.GetRecorder("GET", "/test", nil, nil, nil)
	Write(file, w, true, false)
	disposition := w.Result().Header.Get("Content-Disposition")
	test.IsEqualBool(t, strings.HasPrefix(disposition, "attachment;"), true)
	// encoded form must use %20 for spaces, not +
	test.IsEqualBool(t, strings.Contains(disposition, "+"), false)
	test.IsEqualBool(t, strings.Contains(disposition, "filename*=UTF-8''"), true)
	test.IsEqualBool(t, strings.Contains(disposition, "%20"), true)

	// --- Filename containing a + character ---
	file.Name = "build+(3).zip"
	w, _ = test.GetRecorder("GET", "/test", nil, nil, nil)
	Write(file, w, true, false)
	disposition = w.Result().Header.Get("Content-Disposition")
	// + in the original name must be encoded as %2B, not left bare or turned into a space
	test.IsEqualBool(t, strings.Contains(disposition, "%2B"), true)
	test.IsEqualBool(t, strings.Contains(disposition, "filename*=UTF-8''build%2B%283%29.zip"), true)

	// --- Encrypted file: Last-Modified and Etag must be present and derived from UploadDate/SHA1,
	// not the current time - a resuming client's If-Range can only ever match a validator that
	// stays the same across requests. Accept-Ranges is left to http.ServeContent, which is the
	// component that actually knows whether the reader it was handed can seek.
	file = models.File{Name: "secret.bin", ContentType: "application/octet-stream", SizeBytes: 512, UploadDate: 1700000000, SHA1: "abc123"}
	file.Encryption.IsEncrypted = true
	w, _ = test.GetRecorder("GET", "/test", nil, nil, nil)
	Write(file, w, false, false)
	test.IsEqualString(t, w.Result().Header.Get("Accept-Ranges"), "")
	test.IsEqualString(t, w.Result().Header.Get("Last-Modified"), time.Unix(1700000000, 0).UTC().Format(http.TimeFormat))
	test.IsEqualString(t, w.Result().Header.Get("Etag"), `"abc123"`)

	// --- Two requests for the same file must return the identical validators, not a fresh one
	// each time (this is the pin for the resume bug: a validator that changes every request can
	// never be matched by a later If-Range). ---
	w2, _ := test.GetRecorder("GET", "/test", nil, nil, nil)
	Write(file, w2, false, false)
	test.IsEqualString(t, w2.Result().Header.Get("Last-Modified"), w.Result().Header.Get("Last-Modified"))
	test.IsEqualString(t, w2.Result().Header.Get("Etag"), w.Result().Header.Get("Etag"))

	// --- Encrypted file that requires client decryption: Content-Type must be octet-stream ---
	file.Encryption.IsEndToEndEncrypted = true
	w, _ = test.GetRecorder("GET", "/test", nil, nil, nil)
	Write(file, w, false, false)
	test.IsEqualString(t, w.Result().Header.Get("Content-Type"), "application/octet-stream")

	// --- Encrypted file served decrypted: original Content-Type must be restored ---
	w, _ = test.GetRecorder("GET", "/test", nil, nil, nil)
	Write(file, w, false, true)
	test.IsEqualString(t, w.Result().Header.Get("Content-Type"), "application/octet-stream") // file.ContentType

	// --- Unencrypted file: Accept-Ranges must NOT be set ---
	file = models.File{Name: "plain.txt", ContentType: "text/plain", SizeBytes: 42}
	w, _ = test.GetRecorder("GET", "/test", nil, nil, nil)
	Write(file, w, false, false)
	test.IsEqualString(t, w.Result().Header.Get("Accept-Ranges"), "")
	test.IsEqualString(t, w.Result().Header.Get("Last-Modified"), "")
}
