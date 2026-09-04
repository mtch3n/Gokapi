package downloadsession

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/test"
	"github.com/forceu/gokapi/internal/test/testconfiguration"
)

func TestMain(m *testing.M) {
	testconfiguration.Create(false)
	os.Setenv("GOKAPI_DOWNLOAD_SESSION_SIGN_KEY", "this_is_a_test_key_that_is_exactly_32_chars_")
	configuration.Load()
	result := m.Run()
	testconfiguration.Delete()
	os.Exit(result)
}

const fileId = "downloadSessionFile"

// TestVerifyAcceptsWhatSignIssued is the base case: the token this package mints for a resource
// is accepted for that same resource before it expires.
func TestVerifyAcceptsWhatSignIssued(t *testing.T) {
	token := Sign(models.ShareResourceFile, fileId, 123, 2000)
	_, valid := Verify(token, models.ShareResourceFile, fileId, 1000)
	test.IsEqualBool(t, valid, true)
}

// TestVerifyRefusesAnExpiredToken pins that expiry is enforced from inside the token, which is
// what makes the scheme stateless - there is no server-side record to expire it instead.
func TestVerifyRefusesAnExpiredToken(t *testing.T) {
	token := Sign(models.ShareResourceFile, fileId, 123, 2000)
	_, valid := Verify(token, models.ShareResourceFile, fileId, 2000)
	test.IsEqualBool(t, valid, false)
	_, valid = Verify(token, models.ShareResourceFile, fileId, 2001)
	test.IsEqualBool(t, valid, false)
}

// TestVerifyRefusesAnotherResource is the whole point of binding the id into the payload: a token
// minted by spending a download on one file must not open the window of another. Without this a
// single cheap download would mint a key to every file on the instance.
func TestVerifyRefusesAnotherResource(t *testing.T) {
	token := Sign(models.ShareResourceFile, fileId, 123, 2000)
	_, valid := Verify(token, models.ShareResourceFile, "aDifferentFile", 1000)
	test.IsEqualBool(t, valid, false)
	// A folder and a file could hold the same id string; the type keeps them apart.
	_, valid = Verify(token, models.ShareResourceBundle, fileId, 1000)
	test.IsEqualBool(t, valid, false)
}

// TestVerifyRefusesATamperedToken covers the case the MAC exists for: an attacker who has a valid
// token for their own file rewrites the id, or extends the expiry, and re-presents it.
func TestVerifyRefusesATamperedToken(t *testing.T) {
	token := Sign(models.ShareResourceFile, fileId, 123, 2000)
	encoded, signature, _ := strings.Cut(token, ".")

	// Re-encode the payload with a different resource, keeping the original signature.
	forged := base64.RawURLEncoding.EncodeToString(
		[]byte(`{"v":1,"t":0,"id":"aDifferentFile","r":123,"exp":2000}`)) + "." + signature
	_, valid := Verify(forged, models.ShareResourceFile, "aDifferentFile", 1000)
	test.IsEqualBool(t, valid, false)

	// Keep the payload, corrupt the signature.
	_, valid = Verify(encoded+".AAAA", models.ShareResourceFile, fileId, 1000)
	test.IsEqualBool(t, valid, false)

	// Structurally invalid input must not panic or pass.
	_, valid = Verify("", models.ShareResourceFile, fileId, 1000)
	test.IsEqualBool(t, valid, false)
	_, valid = Verify("noseparator", models.ShareResourceFile, fileId, 1000)
	test.IsEqualBool(t, valid, false)
	_, valid = Verify("!!!.!!!", models.ShareResourceFile, fileId, 1000)
	test.IsEqualBool(t, valid, false)
}

// TestTokenCarriesNoFileMaterial pins R3. The token travels in a URL, so it reaches browser
// history, the download list and proxy logs. Its payload must therefore describe nothing about
// the file beyond the id already visible in that same URL - no name, no content type, no key.
func TestTokenCarriesNoFileMaterial(t *testing.T) {
	token := Sign(models.ShareResourceFile, fileId, 123, 2000)
	encoded, _, _ := strings.Cut(token, ".")
	body, err := base64.RawURLEncoding.DecodeString(encoded)
	test.IsNil(t, err)

	// Exactly five keys, all of them either already in the URL, the recipient id, or a bare timestamp.
	test.IsEqualString(t, string(body), `{"v":1,"t":0,"id":"downloadSessionFile","r":123,"exp":2000}`)
}

// TestVerifyRefusesAnUnknownVersion pins that a future format is rejected rather than misread by
// this one. A payload whose fields happen to line up must not be accepted under the wrong rules.
func TestVerifyRefusesAnUnknownVersion(t *testing.T) {
	signKey := configuration.GetEnvironment().DownloadSessionSignKey
	encoded := base64.RawURLEncoding.EncodeToString(
		[]byte(`{"v":2,"t":0,"id":"` + fileId + `","r":123,"exp":2000}`))
	token := encoded + "." + base64.RawURLEncoding.EncodeToString(sign(encoded, signKey))
	_, valid := Verify(token, models.ShareResourceFile, fileId, 1000)
	test.IsEqualBool(t, valid, false)
}

// TestRecipientIdRoundTrips pins that the recipient id passed to Sign is included in the token
// and readable from the Claims returned by Verify.
func TestRecipientIdRoundTrips(t *testing.T) {
	recipientId := 456
	token := Sign(models.ShareResourceFile, fileId, recipientId, 2000)
	claims, valid := Verify(token, models.ShareResourceFile, fileId, 1000)
	test.IsEqualBool(t, valid, true)
	test.IsEqualInt(t, claims.RecipientId, recipientId)
}

// TestShortKeyRefusesToSign pins that Sign refuses to issue a token when the signing key is
// shorter than 32 bytes, which would silently weaken every token.
func TestShortKeyRefusesToSign(t *testing.T) {
	// Set a short key
	os.Setenv("GOKAPI_DOWNLOAD_SESSION_SIGN_KEY", "short")
	configuration.Load()
	t.Cleanup(func() {
		os.Setenv("GOKAPI_DOWNLOAD_SESSION_SIGN_KEY", "this_is_a_test_key_that_is_exactly_32_chars_")
		configuration.Load()
	})

	token := Sign(models.ShareResourceFile, fileId, 123, 2000)
	test.IsEqualString(t, token, "")
}

// TestShortKeyRefusesToVerify pins the other half of the key check. Verification refuses outright
// rather than comparing against a MAC computed with an inadequate key, and it must do so before
// the comparison: an empty signature and an empty MAC would otherwise compare equal, because
// hmac.Equal reports two zero-length slices as a match.
func TestShortKeyRefusesToVerify(t *testing.T) {
	token := Sign(models.ShareResourceFile, fileId, 123, 2000)
	test.IsEqualBool(t, token != "", true)

	os.Setenv("GOKAPI_DOWNLOAD_SESSION_SIGN_KEY", "short")
	configuration.Load()
	t.Cleanup(func() {
		os.Setenv("GOKAPI_DOWNLOAD_SESSION_SIGN_KEY", "this_is_a_test_key_that_is_exactly_32_chars_")
		configuration.Load()
	})

	_, ok := Verify(token, models.ShareResourceFile, fileId, 1000)
	test.IsEqualBool(t, ok, false)

	_, ok = Verify(fileId+".", models.ShareResourceFile, fileId, 1000)
	test.IsEqualBool(t, ok, false)
}
