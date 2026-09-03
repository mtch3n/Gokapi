package configuration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/forceu/gokapi/internal/configuration/cloudconfig"
	"github.com/forceu/gokapi/internal/configuration/configupgrade"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/test"
	"github.com/forceu/gokapi/internal/test/testconfiguration"
	"golang.org/x/crypto/argon2"
)

func TestMain(m *testing.M) {
	testconfiguration.Create(false)
	exitVal := m.Run()
	testconfiguration.Delete()
	os.Exit(exitVal)
}

func TestLoad(t *testing.T) {
	test.IsEqualBool(t, Exists(), true)
	Load()
	test.IsEqualString(t, parsedEnvironment.ConfigDir, "test")
	test.IsEqualString(t, serverSettings.Port, test.PortDefault)
	test.IsEqualString(t, serverSettings.Authentication.Username, "test")
	test.IsEqualString(t, serverSettings.ServerUrl, test.Url(test.PortDefault)+"/")
	test.IsEqualBool(t, serverSettings.UseSsl, false)

	_ = os.Setenv("GOKAPI_LENGTH_ID", "20")
	_ = os.Setenv("GOKAPI_LENGTH_HOTLINK_ID", "25")
	Load()
	test.IsEqualInt(t, parsedEnvironment.LengthId, 20)
	test.IsEqualInt(t, parsedEnvironment.LengthHotlinkId, 25)
	_ = os.Unsetenv("GOKAPI_LENGTH_ID")
	_ = os.Unsetenv("GOKAPI_LENGTH_HOTLINK_ID")
	test.IsEqualInt(t, serverSettings.ConfigVersion, configupgrade.CurrentConfigVersion)
	testconfiguration.Create(false)
	Load()
}

// hybridFixtureConfig returns a models.Configuration whose shape matches exactly what save()
// writes to disk in production: the whole struct marshalled with json.MarshalIndent, the same
// call ToJson() makes. Crucially this means the returned JSON always contains an explicit
// "OnlyRegisteredUsers" key, because models.AuthenticationConfig.OnlyRegisteredUsers has no
// omitempty tag - there is no such thing as a real config.json missing that key. Tests must build
// fixtures this way instead of hand-writing JSON in a shape no deployment has ever produced.
func hybridFixtureConfig() models.Configuration {
	return models.Configuration{
		Authentication: models.AuthenticationConfig{
			Method:                        models.AuthenticationInternal,
			SaltAdmin:                     "12345678901234567890123",
			SaltFiles:                     "12345678901234567890123",
			Username:                      "admin",
			OAuthEnabledAlongsideInternal: true,
			OAuthProvider:                 "https://example.com",
			OAuthClientId:                 "id",
			OAuthClientSecret:             "secret",
			OAuthRecheckInterval:          1,
		},
		ConfigVersion: configupgrade.CurrentConfigVersion,
		DataDir:       "test",
		DatabaseUrl:   "sqlite://./test/gokapi.sqlite",
	}
}

// TestLoadNormalizesOnlyRegisteredUsersForHybrid verifies that real config.json files
// always carry an explicit "OnlyRegisteredUsers" key (see hybridFixtureConfig), so a check for
// "was the key present" can never distinguish a hand-edited hybrid config from an ordinary one.
// The forcing must be unconditional on Method+OAuthEnabledAlongsideInternal, not gated on key
// presence. Before this fix, a fixture built from the real save() shape - which always writes
// "OnlyRegisteredUsers":false when the field is unset - loaded with OnlyRegisteredUsers still
// false, silently letting any Google account on the internet auto-provision a user.
func TestLoadNormalizesOnlyRegisteredUsersForHybrid(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/config.json"
	cfg := hybridFixtureConfig()
	// OnlyRegisteredUsers is left at its Go zero value (false), exactly like an operator who
	// hand-edited only OAuthEnabledAlongsideInternal into an existing, previously-saved config.
	raw := cfg.ToJson()
	test.IsEqualBool(t, strings.Contains(string(raw), `"OnlyRegisteredUsers": false`), true)
	err := os.WriteFile(path, raw, 0600)
	test.IsNil(t, err)

	settings, err := loadFromFile(path)
	test.IsNil(t, err)
	test.IsEqualBool(t, settings.Authentication.OnlyRegisteredUsers, true)
}

// TestLoadHybridSelfRegistrationOptIn verifies the replacement escape hatch: because forcing is
// now unconditional, an operator who genuinely wants hybrid self-registration must set the
// distinct, dangerous AllowHybridSelfRegistration key (which is omitempty, so it is never present
// by accident). With that opt-in set, OnlyRegisteredUsers is left as the operator wrote it.
func TestLoadHybridSelfRegistrationOptIn(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/config.json"
	cfg := hybridFixtureConfig()
	cfg.Authentication.AllowHybridSelfRegistration = true
	raw := cfg.ToJson()
	err := os.WriteFile(path, raw, 0600)
	test.IsNil(t, err)

	settings, err := loadFromFile(path)
	test.IsNil(t, err)
	test.IsEqualBool(t, settings.Authentication.OnlyRegisteredUsers, false)
	test.IsEqualBool(t, settings.Authentication.AllowHybridSelfRegistration, true)
}

// TestLoadDoesNotNormalizeNonHybrid verifies the normalization is scoped to hybrid auth only: a
// plain internal-auth config built from the real save() shape, with OAuth not enabled alongside
// it, must keep OnlyRegisteredUsers at its ordinary zero value.
func TestLoadDoesNotNormalizeNonHybrid(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/config.json"
	cfg := hybridFixtureConfig()
	cfg.Authentication.OAuthEnabledAlongsideInternal = false
	raw := cfg.ToJson()
	err := os.WriteFile(path, raw, 0600)
	test.IsNil(t, err)

	settings, err := loadFromFile(path)
	test.IsNil(t, err)
	test.IsEqualBool(t, settings.Authentication.OnlyRegisteredUsers, false)
}

func TestLoadFromSetup(t *testing.T) {
	newConfig := models.Configuration{
		Authentication: models.AuthenticationConfig{},
		Port:           "localhost:123",
		ServerUrl:      "serverurl",
		RedirectUrl:    "redirect",
		ConfigVersion:  configupgrade.CurrentConfigVersion,
		DataDir:        "test",
		MaxMemory:      10,
		UseSsl:         true,
		MaxFileSizeMB:  199,
		DatabaseUrl:    "sqlite://./test/gokapi.sqlite",
	}
	newCloudConfig := cloudconfig.CloudConfig{Aws: models.AwsConfig{
		Bucket:    "bucket",
		Region:    "region",
		KeyId:     "keyid",
		KeySecret: "secret",
		Endpoint:  "",
	}}

	testconfiguration.WriteCloudConfigFile(true)
	LoadFromSetup(newConfig, nil, End2EndReconfigParameters{}, "")
	test.FileDoesNotExist(t, "test/cloudconfig.yml")
	test.IsEqualString(t, serverSettings.RedirectUrl, "redirect")

	LoadFromSetup(newConfig, &newCloudConfig, End2EndReconfigParameters{}, "")
	test.FileExists(t, "test/cloudconfig.yml")
	config, ok := cloudconfig.Load()
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, config.Aws.KeyId, "keyid")
	test.IsEqualString(t, serverSettings.ServerUrl, "serverurl")
}

func TestUsesHttps(t *testing.T) {
	usesHttps = false
	test.IsEqualBool(t, UsesHttps(), false)
	usesHttps = true
	test.IsEqualBool(t, UsesHttps(), true)
}

func BenchmarkArgon2id(b *testing.B) {
	salt := []byte(helper.GenerateRandomString(argonSaltLen))
	for i := 0; i < b.N; i++ {
		argon2.IDKey([]byte("password"), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	}
}

func TestHashSha1_KnownVector(t *testing.T) {
	// SHA1("password" + "salt") pre-computed externally for regression
	got := hashSha1("password", "salt")
	// echo -n "passwordsalt" | sha1sum
	want := "c88e9c67041a74e0357befdff93f87dde0904214"
	if got != want {
		t.Errorf("hashSha1 = %q, want %q", got, want)
	}
}

func TestHashSha1_DifferentSaltsDifferentHashes(t *testing.T) {
	h1 := hashSha1("password", "salt1")
	h2 := hashSha1("password", "salt2")
	if h1 == h2 {
		t.Error("different salts should produce different hashes")
	}
}

func TestHashSha1_DifferentPasswordsDifferentHashes(t *testing.T) {
	h1 := hashSha1("password1", "salt")
	h2 := hashSha1("password2", "salt")
	if h1 == h2 {
		t.Error("different passwords should produce different hashes")
	}
}

func TestHashSha1_OutputIs40Chars(t *testing.T) {
	got := hashSha1("password", "salt")
	if len(got) != 40 {
		t.Errorf("SHA1 hex output should be 40 chars, got %d", len(got))
	}
}

// --- HashPassword ---

func TestHashPassword_EmptyPasswordReturnsEmpty(t *testing.T) {
	got := HashPassword("", false, "")
	if got != "" {
		t.Errorf("empty password should return empty string, got %q", got)
	}
}

func TestHashPassword_LegacyPanicOnEmptySalt(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic with empty legacy salt, got none")
		}
	}()
	HashPassword("password", true, "")
}

func TestHashPassword_LegacyMatchesSha1(t *testing.T) {
	got := HashPassword("password", true, "mysalt")
	want := hashSha1("password", "mysalt")
	if got != want {
		t.Errorf("legacy hash = %q, want %q", got, want)
	}
}

func TestHashPassword_Argon2idFormat(t *testing.T) {
	got := HashPassword("password", false, "")
	parts := strings.Split(got, "$")
	if len(parts) != 3 {
		t.Fatalf("expected 3 $-separated parts, got %d: %q", len(parts), got)
	}
	if parts[0] != "argon2id" {
		t.Errorf("prefix = %q, want %q", parts[0], "argon2id")
	}
	if len(parts[1]) == 0 {
		t.Error("salt segment should not be empty")
	}
	if len(parts[2]) == 0 {
		t.Error("hash segment should not be empty")
	}
}

func TestHashPassword_Argon2idUniqueSaltsEachCall(t *testing.T) {
	h1 := HashPassword("password", false, "")
	h2 := HashPassword("password", false, "")
	if h1 == h2 {
		t.Error("two calls with same password should produce different hashes (random salt)")
	}
}

func TestHashPassword_Argon2idDifferentPasswordsDifferentHashes(t *testing.T) {
	// Same underlying salt is impossible to force, but hashes should differ
	h1 := HashPassword("password1", false, "")
	h2 := HashPassword("password2", false, "")
	if h1 == h2 {
		t.Error("different passwords should produce different hashes")
	}
}

// --- VerifyPassword ---

func TestVerifyPassword_LegacyCorrectPassword(t *testing.T) {
	stored := hashSha1("password", "mysalt")
	ok, needsRehash := VerifyPassword("password", stored, "mysalt")
	if !ok {
		t.Error("expected correct legacy password to verify")
	}
	if !needsRehash {
		t.Error("legacy hash should signal needsRehash=true")
	}
}

func TestVerifyPassword_LegacyWrongPassword(t *testing.T) {
	stored := hashSha1("password", "mysalt")
	ok, needsRehash := VerifyPassword("wrongpassword", stored, "mysalt")
	if ok {
		t.Error("wrong password should not verify")
	}
	if !needsRehash {
		t.Error("legacy hash should signal needsRehash=true even on failure")
	}
}

func TestVerifyPassword_Argon2idCorrectPassword(t *testing.T) {
	stored := HashPassword("password", false, "")
	ok, needsRehash := VerifyPassword("password", stored, "")
	if !ok {
		t.Error("correct argon2id password should verify")
	}
	if needsRehash {
		t.Error("argon2id hash should not signal needsRehash")
	}
}

func TestVerifyPassword_Argon2idWrongPassword(t *testing.T) {
	stored := HashPassword("password", false, "")
	ok, needsRehash := VerifyPassword("wrongpassword", stored, "")
	if ok {
		t.Error("wrong password should not verify against argon2id hash")
	}
	if needsRehash {
		t.Error("argon2id hash should not signal needsRehash")
	}
}

func TestVerifyPassword_MalformedHashReturnsFalse(t *testing.T) {
	cases := []string{
		"",
		"notahash",
		"argon2id$onlytwoparts",
		"wrongprefix$abc$def",
		"argon2id$notvalidhex!!!$abc123",
	}
	for _, stored := range cases {
		ok, needsRehash := VerifyPassword("password", stored, "")
		if ok {
			t.Errorf("malformed hash %q should not verify", stored)
		}
		if needsRehash {
			t.Errorf("malformed hash %q should not signal needsRehash", stored)
		}
	}
}

func TestVerifyPassword_EmptyPasswordNeverVerifies(t *testing.T) {
	stored := HashPassword("password", false, "")
	ok, _ := VerifyPassword("", stored, "")
	if ok {
		t.Error("empty password should not verify against a real hash")
	}
}

// --- Round-trip / migration ---

func TestRoundTrip_Argon2id(t *testing.T) {
	passwords := []string{"correct horse battery staple", "P@ssw0rd!", "unicode:日本語"}
	for _, pw := range passwords {
		stored := HashPassword(pw, false, "")
		ok, needsRehash := VerifyPassword(pw, stored, "")
		if !ok {
			t.Errorf("round-trip failed for password %q", pw)
		}
		if needsRehash {
			t.Errorf("needsRehash should be false for argon2id, password %q", pw)
		}
	}
}

func TestMigration_LegacyToArgon2id(t *testing.T) {
	// Simulate the on-login rehash migration path
	const password = "oldpassword"
	const salt = "legacysalt"

	legacyHash := HashPassword(password, true, salt)

	// User logs in: verify with legacy, then rehash
	ok, needsRehash := VerifyPassword(password, legacyHash, salt)
	if !ok || !needsRehash {
		t.Fatal("legacy verification failed or did not signal rehash")
	}

	newHash := HashPassword(password, false, "")

	// Subsequent logins use new argon2id hash
	ok, needsRehash = VerifyPassword(password, newHash, "")
	if !ok {
		t.Error("password should verify after migration")
	}
	if needsRehash {
		t.Error("should not need rehash after migration")
	}
}

func TestValidatePasswordComplexity(t *testing.T) {
	test.IsNil(t, ValidatePasswordComplexity("Passw0rd!"))
	// The fourth class is anything that is not a letter or a digit, so a space
	// and a non-ASCII symbol both satisfy it.
	test.IsNil(t, ValidatePasswordComplexity("Passw0rd "))
	test.IsNil(t, ValidatePasswordComplexity("Passw0rd§"))

	test.IsNotNil(t, ValidatePasswordComplexity("PASSW0RD!"))
	test.IsNotNil(t, ValidatePasswordComplexity("passw0rd!"))
	test.IsNotNil(t, ValidatePasswordComplexity("Password!"))
	test.IsNotNil(t, ValidatePasswordComplexity("Passw0rd"))
	test.IsNotNil(t, ValidatePasswordComplexity(""))
}

// TestValidatePasswordComplexityMatchesFrontendFixture reads the shared vectors from
// frontend/testdata/password-classification.json and checks ValidatePasswordComplexity's
// per-class classification against every one of them, so the Go and TypeScript
// implementations cannot silently drift apart again the way they did before: the frontend
// used ASCII-only regexes while this function uses unicode.IsLower/IsUpper/IsDigit, and a
// password with a non-ASCII letter passed client-side validation but was then rejected by
// the server after every chunk had already uploaded.
//
// The fixture lives in the frontend repository, a sibling directory of this one, not inside
// this repo. It is referenced by relative path from this file rather than copied in, because
// a copy would drift exactly like the two implementations did. That means this test only
// finds the fixture when backend/ and frontend/ are checked out side by side; a standalone
// clone of this repo (as it is a public fork) does not have the frontend tree, so the test
// skips instead of failing in that case.
func TestValidatePasswordComplexityMatchesFrontendFixture(t *testing.T) {
	fixturePath := passwordClassificationFixturePath()
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Skipf("frontend password-classification fixture not found at %s (expected backend/ and frontend/ as sibling directories): %v", fixturePath, err)
	}

	var fixture struct {
		Vectors []struct {
			Name     string `json:"name"`
			Password string `json:"password"`
			Lower    bool   `json:"lower"`
			Upper    bool   `json:"upper"`
			Digit    bool   `json:"digit"`
			Special  bool   `json:"special"`
		} `json:"vectors"`
	}
	err = json.Unmarshal(data, &fixture)
	if err != nil {
		t.Fatalf("failed to parse %s: %v", fixturePath, err)
	}
	if len(fixture.Vectors) == 0 {
		t.Fatalf("%s contained no vectors", fixturePath)
	}

	for _, vector := range fixture.Vectors {
		vector := vector
		t.Run(vector.Name, func(t *testing.T) {
			test.IsEqualBool(t, passwordHasLower(vector.Password), vector.Lower)
			test.IsEqualBool(t, passwordHasUpper(vector.Password), vector.Upper)
			test.IsEqualBool(t, passwordHasDigit(vector.Password), vector.Digit)
			test.IsEqualBool(t, passwordHasSpecial(vector.Password), vector.Special)
		})
	}
}

// passwordClassificationFixturePath resolves the shared fixture relative to this source
// file's own location, rather than the process working directory, so `go test` behaves the
// same whether it is invoked from this package, the repo root or anywhere else.
func passwordClassificationFixturePath() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "frontend", "testdata", "password-classification.json")
}

// ValidatePasswordComplexity only reports pass/fail for "all four classes present", stopping
// at the first missing class rather than listing every one that is missing. The four
// passwordHasX probes below recover a single class's presence in isolation: each pads the
// password with filler characters that cover the other three required classes, so the only
// class that can still be missing from that combined string is the one under test.
func passwordHasLower(password string) bool {
	return ValidatePasswordComplexity(password+fillerUpper+fillerDigit+fillerSpecial) == nil
}

func passwordHasUpper(password string) bool {
	return ValidatePasswordComplexity(password+fillerLower+fillerDigit+fillerSpecial) == nil
}

func passwordHasDigit(password string) bool {
	return ValidatePasswordComplexity(password+fillerLower+fillerUpper+fillerSpecial) == nil
}

func passwordHasSpecial(password string) bool {
	return ValidatePasswordComplexity(password+fillerLower+fillerUpper+fillerDigit) == nil
}

const (
	fillerLower   = "a"
	fillerUpper   = "A"
	fillerDigit   = "1"
	fillerSpecial = "!"
)

func TestValidateSharePasswordComplexity(t *testing.T) {
	// ValidateSharePassword reads the minimum length from the environment, which
	// panics until it has been parsed. Without this the test only passes when an
	// earlier test in the package happened to load it first.
	Load()

	// Long enough but only one character class: length alone must not be
	// enough to protect a share.
	_, err := ValidateSharePassword("passwordpassword", true)
	test.IsNotNil(t, err)

	trimmed, err := ValidateSharePassword("  Passw0rd!x  ", true)
	test.IsNil(t, err)
	test.IsEqualString(t, trimmed, "Passw0rd!x")

	// No password requested stays the legitimate default.
	trimmed, err = ValidateSharePassword("", false)
	test.IsNil(t, err)
	test.IsEqualString(t, trimmed, "")
}
