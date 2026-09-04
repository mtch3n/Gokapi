package downloadsession

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/test"
	"github.com/forceu/gokapi/internal/test/testconfiguration"
)

func TestMain(m *testing.M) {
	testconfiguration.Create(false)
	configuration.Load()
	m.Run()
	testconfiguration.Delete()
}

const fileId = "downloadSessionFile"

// TestVerifyAcceptsWhatSignIssued is the base case: the token this package mints for a resource
// is accepted for that same resource before it expires.
func TestVerifyAcceptsWhatSignIssued(t *testing.T) {
	token := Sign(models.ShareResourceFile, fileId, 2000)
	test.IsEqualBool(t, Verify(token, models.ShareResourceFile, fileId, 1000), true)
}

// TestVerifyRefusesAnExpiredToken pins that expiry is enforced from inside the token, which is
// what makes the scheme stateless - there is no server-side record to expire it instead.
func TestVerifyRefusesAnExpiredToken(t *testing.T) {
	token := Sign(models.ShareResourceFile, fileId, 2000)
	test.IsEqualBool(t, Verify(token, models.ShareResourceFile, fileId, 2000), false)
	test.IsEqualBool(t, Verify(token, models.ShareResourceFile, fileId, 2001), false)
}

// TestVerifyRefusesAnotherResource is the whole point of binding the id into the payload: a token
// minted by spending a download on one file must not open the window of another. Without this a
// single cheap download would mint a key to every file on the instance.
func TestVerifyRefusesAnotherResource(t *testing.T) {
	token := Sign(models.ShareResourceFile, fileId, 2000)
	test.IsEqualBool(t, Verify(token, models.ShareResourceFile, "aDifferentFile", 1000), false)
	// A folder and a file could hold the same id string; the type keeps them apart.
	test.IsEqualBool(t, Verify(token, models.ShareResourceBundle, fileId, 1000), false)
}

// TestVerifyRefusesATamperedToken covers the case the MAC exists for: an attacker who has a valid
// token for their own file rewrites the id, or extends the expiry, and re-presents it.
func TestVerifyRefusesATamperedToken(t *testing.T) {
	token := Sign(models.ShareResourceFile, fileId, 2000)
	encoded, signature, _ := strings.Cut(token, ".")

	// Re-encode the payload with a different resource, keeping the original signature.
	forged := base64.RawURLEncoding.EncodeToString(
		[]byte(`{"v":1,"t":0,"id":"aDifferentFile","exp":2000}`)) + "." + signature
	test.IsEqualBool(t, Verify(forged, models.ShareResourceFile, "aDifferentFile", 1000), false)

	// Keep the payload, corrupt the signature.
	test.IsEqualBool(t, Verify(encoded+".AAAA", models.ShareResourceFile, fileId, 1000), false)

	// Structurally invalid input must not panic or pass.
	test.IsEqualBool(t, Verify("", models.ShareResourceFile, fileId, 1000), false)
	test.IsEqualBool(t, Verify("noseparator", models.ShareResourceFile, fileId, 1000), false)
	test.IsEqualBool(t, Verify("!!!.!!!", models.ShareResourceFile, fileId, 1000), false)
}

// TestTokenCarriesNoFileMaterial pins R3. The token travels in a URL, so it reaches browser
// history, the download list and proxy logs. Its payload must therefore describe nothing about
// the file beyond the id already visible in that same URL - no name, no content type, no key.
func TestTokenCarriesNoFileMaterial(t *testing.T) {
	token := Sign(models.ShareResourceFile, fileId, 2000)
	encoded, _, _ := strings.Cut(token, ".")
	body, err := base64.RawURLEncoding.DecodeString(encoded)
	test.IsNil(t, err)

	// Exactly four keys, all of them either already in the URL or a bare timestamp.
	test.IsEqualString(t, string(body), `{"v":1,"t":0,"id":"downloadSessionFile","exp":2000}`)
}

// TestVerifyRefusesAnUnknownVersion pins that a future format is rejected rather than misread by
// this one. A payload whose fields happen to line up must not be accepted under the wrong rules.
func TestVerifyRefusesAnUnknownVersion(t *testing.T) {
	encoded := base64.RawURLEncoding.EncodeToString(
		[]byte(`{"v":2,"t":0,"id":"` + fileId + `","exp":2000}`))
	token := encoded + "." + base64.RawURLEncoding.EncodeToString(sign(encoded))
	test.IsEqualBool(t, Verify(token, models.ShareResourceFile, fileId, 1000), false)
}
