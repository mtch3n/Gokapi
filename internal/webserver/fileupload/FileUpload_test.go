package fileupload

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/encryption"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/test"
	"github.com/forceu/gokapi/internal/test/testconfiguration"
)

func TestMain(m *testing.M) {
	testconfiguration.Create(false)
	configuration.Load()
	configuration.ConnectDatabase()
	exitVal := m.Run()
	testconfiguration.Delete()
	os.Exit(exitVal)
}

func TestParseConfig(t *testing.T) {
	data := testData{
		allowedDownloads: "9",
		expiryDays:       "5",
		password:         "LongEnoughPw1!",
		isE2E:            "",
		realSize:         "",
	}
	config, err := parseConfig(data)
	test.IsNil(t, err)
	test.IsEqualBool(t, config.IsEndToEndEncrypted, false)
	test.IsEqualInt64(t, config.RealSize, 0)

	test.IsEqualInt(t, config.AllowedDownloads, 9)
	test.IsEqualString(t, config.Password, "LongEnoughPw1!")
	test.IsEqualInt(t, config.Expiry, 5)

	config, err = parseConfig(data)
	test.IsNil(t, err)

	data.allowedDownloads = ""
	data.expiryDays = "invalid"

	config, err = parseConfig(data)
	test.IsNil(t, err)
	test.IsEqualInt(t, config.AllowedDownloads, 1)
	test.IsEqualInt(t, config.Expiry, 14)
	test.IsEqualBool(t, config.UnlimitedTime, false)
	test.IsEqualBool(t, config.UnlimitedDownload, false)

	data.allowedDownloads = "0"
	data.expiryDays = "0"
	config, err = parseConfig(data)
	test.IsNil(t, err)
	test.IsEqualBool(t, config.UnlimitedTime, true)
	test.IsEqualBool(t, config.UnlimitedDownload, true)

	// isE2E is only honoured while the server is configured for end-to-end
	// encryption; the server, not the caller, is authoritative here (F2).
	data.isE2E = "true"
	data.realSize = "200"
	previousLevel := configuration.Get().Encryption.Level
	defer func() { configuration.Get().Encryption.Level = previousLevel }()

	configuration.Get().Encryption.Level = encryption.FullEncryptionStored
	config, err = parseConfig(data)
	test.IsNotNil(t, err)
	test.IsEqualBool(t, errors.Is(err, ErrE2ENotConfigured), true)

	configuration.Get().Encryption.Level = encryption.EndToEndEncryption
	config, err = parseConfig(data)
	test.IsNil(t, err)
	test.IsEqualBool(t, config.IsEndToEndEncrypted, true)
	test.IsEqualInt64(t, config.RealSize, 200)
}

// TestParseConfigRejectsWhitespaceOnlyPassword closes the confidentiality bug where a
// password field that ends up all whitespace was silently treated the same as no
// password at all, producing an unprotected upload while the caller believed it was
// protected. Unlike a header value, a form field is not trimmed by the transport, so
// this reproduces the exact string a real whitespace-only submission would carry.
func TestParseConfigRejectsWhitespaceOnlyPassword(t *testing.T) {
	data := testData{password: "   "}
	_, err := parseConfig(data)
	test.IsNotNil(t, err)
	test.IsEqualBool(t, errors.Is(err, configuration.ErrSharePasswordTooShort), true)
}

func TestParseConfigRejectsShortPassword(t *testing.T) {
	data := testData{password: "short1"}
	_, err := parseConfig(data)
	test.IsNotNil(t, err)
	test.IsEqualBool(t, errors.Is(err, configuration.ErrSharePasswordTooShort), true)
}

// TestParseConfigAllowsAbsentPassword confirms that not supplying a password at all -
// the ordinary "this upload has no password" case - is still accepted without error.
func TestParseConfigAllowsAbsentPassword(t *testing.T) {
	data := testData{password: ""}
	config, err := parseConfig(data)
	test.IsNil(t, err)
	test.IsEqualString(t, config.Password, "")
}

func TestParseConfigAllowsValidPassword(t *testing.T) {
	data := testData{password: "ValidPassword1!"}
	config, err := parseConfig(data)
	test.IsNil(t, err)
	test.IsEqualString(t, config.Password, "ValidPassword1!")
}

func TestProcess(t *testing.T) {
	w, r := test.GetRecorder("POST", "/upload", nil, nil, strings.NewReader("invalid§$%&%§"))
	err := ProcessCompleteFile(w, r, 9, 20)
	test.IsNotNil(t, err)

	w = httptest.NewRecorder()
	r = getFileUploadRecorder(false)
	err = ProcessCompleteFile(w, r, 9, 20)
	test.IsNil(t, err)
	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	result := models.Result{}
	err = json.Unmarshal(body, &result)
	test.IsNil(t, err)
	test.IsEqualString(t, result.Result, "OK")
	test.IsEqualString(t, result.FileInfo.UrlDownload, "http://127.0.0.1:53843/d?id="+result.FileInfo.Id)
	test.IsEqualString(t, result.FileInfo.UrlHotlink, "http://127.0.0.1:53843/downloadFile?id="+result.FileInfo.Id)
	test.IsEqualString(t, result.FileInfo.Name, "testFile")
	test.IsEqualString(t, result.FileInfo.Size, "11 B")
	test.IsEqualBool(t, result.FileInfo.UnlimitedTime, false)
	test.IsEqualBool(t, result.FileInfo.UnlimitedDownloads, false)
	test.IsEqualInt(t, result.FileInfo.UploaderId, 9)
}

func TestProcessNewChunk(t *testing.T) {
	w, r := test.GetRecorder("POST", "/uploadChunk", nil, nil, strings.NewReader("invalid§$%&%§"))
	_, err := ProcessNewChunk(w, r, false, "", 100*1000*1000)
	test.IsNotNil(t, err)

	w = httptest.NewRecorder()
	r = getFileUploadRecorder(false)
	_, err = ProcessNewChunk(w, r, false, "", 100*1000*1000)
	test.IsNotNil(t, err)

	w = httptest.NewRecorder()
	r = getFileUploadRecorder(true)
	_, err = ProcessNewChunk(w, r, false, "", 100*1000*1000)
	test.IsNil(t, err)
	response, err := io.ReadAll(w.Result().Body)
	test.IsNil(t, err)
	test.IsEqualString(t, string(response), "{\"result\":\"OK\"}")
}

func TestCompleteChunk(t *testing.T) {
	body := strings.NewReader("%")
	r := httptest.NewRequest(http.MethodPost, "/upload", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, _, _, err := ParseFileHeader(r)
	test.IsNotNil(t, err)

	w := httptest.NewRecorder()
	r = getFileUploadRecorder(false)
	_, _, _, err = ParseFileHeader(r)
	test.IsNotNil(t, err)

	data := url.Values{}
	data.Set("isE2E", "true")
	data.Set("realSize", "none")
	w, r = test.GetRecorder("POST", "/uploadComplete", nil, nil, strings.NewReader(data.Encode()))
	r.Header.Set("Content-type", "application/x-www-form-urlencoded")
	chunkId, header, config, err := ParseFileHeader(r)
	test.IsNotNil(t, err)

	data.Del("isE2E")
	data.Del("realSize")
	data.Set("allowedDownloads", "9")
	data.Set("expiryDays", "5")
	data.Set("password", "LongEnoughPw1!")
	data.Set("chunkid", "randomchunkuuid")
	data.Set("filename", "random.file")
	data.Set("filesize", "13")
	w, r = test.GetRecorder("POST", "/uploadComplete", nil, nil, strings.NewReader(data.Encode()))
	r.Header.Set("Content-type", "application/x-www-form-urlencoded")
	chunkId, header, config, err = ParseFileHeader(r)
	test.IsNil(t, err)
	file, err := CompleteChunk(chunkId, header, 9, config)
	test.IsNil(t, err)
	test.IsEqualString(t, file.Name, "random.file")

	response, err := io.ReadAll(w.Result().Body)
	test.IsNil(t, err)
	test.IsEqualString(t, string(response), "")

	data.Set("chunkid", "invalid")
	w, r = test.GetRecorder("POST", "/uploadComplete", nil, nil, strings.NewReader(data.Encode()))
	r.Header.Set("Content-type", "application/x-www-form-urlencoded")
	_, _, _, err = ParseFileHeader(r)
	test.IsNil(t, err)
	_, err = CompleteChunk(chunkId, header, 9, config)
	test.IsNotNil(t, err)
}

// TestCompleteChunkRejectsWhitespaceOnlyPassword closes the confidentiality bug for the
// chunked upload path: a password that is present but all whitespace must be refused
// with an error at the parsing stage, before a file is ever created, rather than
// silently producing an unprotected file.
func TestCompleteChunkRejectsWhitespaceOnlyPassword(t *testing.T) {
	data := url.Values{}
	data.Set("allowedDownloads", "9")
	data.Set("expiryDays", "5")
	data.Set("password", "   ")
	data.Set("chunkid", "randomchunkuuid")
	data.Set("filename", "random.file")
	data.Set("filesize", "13")
	_, r := test.GetRecorder("POST", "/uploadComplete", nil, nil, strings.NewReader(data.Encode()))
	r.Header.Set("Content-type", "application/x-www-form-urlencoded")
	_, _, _, err := ParseFileHeader(r)
	test.IsNotNil(t, err)
	test.IsEqualBool(t, errors.Is(err, configuration.ErrSharePasswordTooShort), true)
}

func getFileUploadRecorder(addChunkInfo bool) *http.Request {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	if addChunkInfo {
		w.WriteField("dztotalfilesize", "13")
		w.WriteField("dzchunkbyteoffset", "0")
		w.WriteField("dzuuid", "randomchunkuuid")
	}
	writer, _ := w.CreateFormFile("file", "testFile")
	io.WriteString(writer, "testContent")
	w.Close()
	r := httptest.NewRequest("POST", "/upload", &b)
	r.Header.Set("Content-Type", w.FormDataContentType())
	if !addChunkInfo {
		r.Header.Add("allowedDownloads", "9")
		r.Header.Add("expiryDays", "5")
		r.Header.Add("password", "123")
	}
	return r
}

type testData struct {
	allowedDownloads, expiryDays, password, isE2E, realSize string
}

func (t testData) Get(key string) string {
	field := reflect.ValueOf(&t).Elem().FieldByName(key)
	if field.IsValid() {
		return field.String()
	}
	return ""
}

func TestApplyMaxExpiry(t *testing.T) {
	// Unset: upstream behaviour, permanent files still allowed
	os.Unsetenv("GOKAPI_MAX_EXPIRY")
	days, unlimited := applyMaxExpiry(30, false)
	test.IsEqualInt(t, days, 30)
	test.IsEqualBool(t, unlimited, false)
	days, unlimited = applyMaxExpiry(0, true)
	test.IsEqualInt(t, days, 0)
	test.IsEqualBool(t, unlimited, true)

	os.Setenv("GOKAPI_MAX_EXPIRY", "7d")
	defer os.Unsetenv("GOKAPI_MAX_EXPIRY")

	// A permanent upload is forced to the cap. This is the file-request case,
	// which is created with unlimitedTime set.
	days, unlimited = applyMaxExpiry(0, true)
	test.IsEqualInt(t, days, 7)
	test.IsEqualBool(t, unlimited, false)

	// A longer expiry is clamped
	days, unlimited = applyMaxExpiry(30, false)
	test.IsEqualInt(t, days, 7)
	test.IsEqualBool(t, unlimited, false)

	// A shorter expiry is left alone
	days, unlimited = applyMaxExpiry(3, false)
	test.IsEqualInt(t, days, 3)
	test.IsEqualBool(t, unlimited, false)

	// Exactly the cap is allowed
	days, _ = applyMaxExpiry(7, false)
	test.IsEqualInt(t, days, 7)

	// A zero or negative expiry without the unlimited flag also gets the cap
	days, unlimited = applyMaxExpiry(0, false)
	test.IsEqualInt(t, days, 7)
	test.IsEqualBool(t, unlimited, false)
}

func TestCreateUploadConfigWithExpiryTimestamp(t *testing.T) {
	os.Unsetenv("GOKAPI_MAX_EXPIRY")

	// A non-zero expiryTimestamp takes precedence over expiryDays and passes through
	// unchanged when no maximum is configured.
	wanted := time.Now().Add(3 * 24 * time.Hour).Unix()
	config, err := CreateUploadConfig(0, 14, wanted, "", false, true, false, 0, "", "", false)
	test.IsNil(t, err)
	test.IsEqualInt64(t, config.ExpiryTimestamp, wanted)
	test.IsEqualBool(t, config.UnlimitedTime, false)

	// With a maximum configured, an expiryTimestamp beyond it is clamped, at the
	// timestamp's own precision rather than rounded up to whole days.
	os.Setenv("GOKAPI_MAX_EXPIRY", "12h")
	defer os.Unsetenv("GOKAPI_MAX_EXPIRY")
	latest := time.Now().Add(12 * time.Hour).Unix()
	config, err = CreateUploadConfig(0, 0, wanted, "", false, true, false, 0, "", "", false)
	test.IsNil(t, err)
	test.IsEqualBool(t, config.UnlimitedTime, false)
	test.IsEqualBool(t, config.ExpiryTimestamp <= latest+2 && config.ExpiryTimestamp >= latest-2, true)
}

func TestCreateUploadConfigEnforcesExpiry(t *testing.T) {
	os.Setenv("GOKAPI_MAX_EXPIRY", "7d")
	defer os.Unsetenv("GOKAPI_MAX_EXPIRY")

	// The file-request path asks for an unlimited lifetime; it must not get one
	config, err := CreateUploadConfig(0, 0, 0, "", true, true, false, 0, "somerequest", "", false)
	test.IsNil(t, err)
	test.IsEqualBool(t, config.UnlimitedTime, false)
	test.IsEqualInt(t, config.Expiry, 7)
	test.IsEqualBool(t, config.ExpiryTimestamp > time.Now().Unix(), true)
}

// TestCreateUploadConfigRejectsE2EWhenNotConfigured is the choke-point test for F2:
// the server, not a client-supplied isEnd2End flag, must decide whether a file is
// end-to-end encrypted. Asserting E2E at any level other than EndToEndEncryption
// must be rejected, and the flag must keep working once that level is configured.
func TestCreateUploadConfigRejectsE2EWhenNotConfigured(t *testing.T) {
	previousLevel := configuration.Get().Encryption.Level
	defer func() { configuration.Get().Encryption.Level = previousLevel }()

	for _, level := range []int{encryption.NoEncryption, encryption.LocalEncryptionStored,
		encryption.LocalEncryptionInput, encryption.FullEncryptionStored, encryption.FullEncryptionInput} {
		configuration.Get().Encryption.Level = level
		_, err := CreateUploadConfig(1, 14, 0, "", false, false, true, 100, "", "", false)
		test.IsNotNil(t, err)
		test.IsEqualBool(t, errors.Is(err, ErrE2ENotConfigured), true)
	}

	configuration.Get().Encryption.Level = encryption.EndToEndEncryption
	config, err := CreateUploadConfig(1, 14, 0, "", false, false, true, 100, "", "", false)
	test.IsNil(t, err)
	test.IsEqualBool(t, config.IsEndToEndEncrypted, true)
	test.IsEqualInt64(t, config.RealSize, 100)

	// Unchanged behaviour: isEnd2End=false never triggers the check, regardless of level.
	configuration.Get().Encryption.Level = encryption.NoEncryption
	config, err = CreateUploadConfig(1, 14, 0, "", false, false, false, 0, "", "", false)
	test.IsNil(t, err)
	test.IsEqualBool(t, config.IsEndToEndEncrypted, false)
}

func TestClampExpiryTimestamp(t *testing.T) {
	// Unset: upstream behaviour preserved, permanent files still allowed
	os.Unsetenv("GOKAPI_MAX_EXPIRY")
	future := time.Now().Add(365 * 24 * time.Hour).Unix()
	ts, unlimited := ClampExpiryTimestamp(future, false)
	test.IsEqualBool(t, ts == future, true)
	test.IsEqualBool(t, unlimited, false)
	_, unlimited = ClampExpiryTimestamp(0, true)
	test.IsEqualBool(t, unlimited, true)

	os.Setenv("GOKAPI_MAX_EXPIRY", "30d")
	defer os.Unsetenv("GOKAPI_MAX_EXPIRY")
	latest := time.Now().Add(30 * 24 * time.Hour).Unix()

	// An unlimited lifetime is refused and pinned to the cap
	ts, unlimited = ClampExpiryTimestamp(0, true)
	test.IsEqualBool(t, unlimited, false)
	test.IsEqualBool(t, ts <= latest+2 && ts >= latest-2, true)

	// An expiry a year out is clamped back to the cap
	ts, unlimited = ClampExpiryTimestamp(future, false)
	test.IsEqualBool(t, unlimited, false)
	test.IsEqualBool(t, ts <= latest+2, true)

	// An expiry inside the cap is left untouched
	soon := time.Now().Add(3 * 24 * time.Hour).Unix()
	ts, unlimited = ClampExpiryTimestamp(soon, false)
	test.IsEqualInt(t, int(ts), int(soon))
	test.IsEqualBool(t, unlimited, false)

	// A zero or negative timestamp without the unlimited flag also gets the cap
	ts, _ = ClampExpiryTimestamp(0, false)
	test.IsEqualBool(t, ts <= latest+2 && ts >= latest-2, true)
}
