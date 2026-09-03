package environment

import (
	"github.com/forceu/gokapi/internal/test"
	"os"
	"reflect"
	"testing"
	"time"
)

var returnCode = 0

func TestMain(m *testing.M) {

	osExit = func(code int) {
		returnCode = code
	}
	exitVal := m.Run()
	os.Exit(exitVal)
}

func TestTempDir(t *testing.T) {
	test.IsEqualString(t, os.Getenv("TMPDIR"), "")
	New()
	test.IsEqualString(t, os.Getenv("TMPDIR"), "")
	IsDocker = "true"
	New()
	test.IsEqualString(t, os.Getenv("TMPDIR"), "data")
	os.Setenv("TMPDIR", "test")
	New()
	test.IsEqualString(t, os.Getenv("TMPDIR"), "test")
	os.Unsetenv("TMPDIR")
	IsDocker = "false"
}

func TestEnvLoad(t *testing.T) {
	os.Setenv("GOKAPI_CONFIG_DIR", "test")
	os.Setenv("GOKAPI_CONFIG_FILE", "test2")
	os.Setenv("GOKAPI_LENGTH_ID", "7")
	env := New()
	test.IsEqualString(t, env.ConfigPath, "test/test2")
	test.IsEqualInt(t, env.LengthId, 7)
	os.Setenv("GOKAPI_LENGTH_ID", "3")
	env = New()
	test.IsEqualInt(t, env.LengthId, 5)
	os.Setenv("GOKAPI_LENGTH_ID", "86")
	env = New()
	test.IsEqualInt(t, env.LengthId, 86)
	os.Unsetenv("GOKAPI_LENGTH_ID")
	os.Setenv("GOKAPI_MIN_LENGTH_PASSWORD", "12")
	env = New()
	test.IsEqualInt(t, env.MinLengthPassword, 12)
	os.Unsetenv("GOKAPI_MIN_LENGTH_PASSWORD")
	env = New()
	os.Setenv("GOKAPI_LENGTH_ID", "15")
	os.Setenv("GOKAPI_MAX_MEMORY_UPLOAD", "0")
	os.Setenv("GOKAPI_MAX_FILESIZE", "0")
	env = New()
	test.IsEqualInt(t, env.LengthId, 15)
	test.IsEqualInt(t, env.MaxFileSize, 5)
	test.IsEqualInt(t, env.MaxMemory, 5)
	os.Setenv("GOKAPI_MAX_FILESIZE", "invalid")
	returnCode = 0
	New()
	test.IsEqualInt(t, returnCode, 1)
	os.Unsetenv("GOKAPI_MAX_FILESIZE")
}

// TestDefaultExpiry pins GOKAPI_DEFAULT_EXPIRY. Every expected value below is a duration
// literal rather than a value read back out of ExpiryOptions, so none of these assertions can
// keep passing if the built-in default or the built-in option list is changed.
func TestDefaultExpiry(t *testing.T) {
	const hour = int64(time.Hour)
	const day = int64(24 * time.Hour)

	// Unset, against the shipped six-preset list: 7d, and not the longest preset.
	os.Unsetenv("GOKAPI_DEFAULT_EXPIRY")
	os.Unsetenv("GOKAPI_MAX_EXPIRY")
	os.Setenv("GOKAPI_EXPIRY_OPTIONS", "1h,1d,7d,14d,30d,365d")
	env := New()
	test.IsEqualInt64(t, int64(env.DefaultExpiry), 7*day)
	test.IsEqualBool(t, int64(env.DefaultExpiry) == 365*day, false)

	// Unset, against a shortened three-preset list: still 7d, and still not the longest preset.
	// This is the case a client-side rule sized against the six-preset list gets wrong.
	os.Setenv("GOKAPI_EXPIRY_OPTIONS", "1d,7d,14d")
	env = New()
	test.IsEqualInt64(t, int64(env.DefaultExpiry), 7*day)
	test.IsEqualBool(t, int64(env.DefaultExpiry) == 14*day, false)

	// A set value is honoured.
	os.Setenv("GOKAPI_DEFAULT_EXPIRY", "1d")
	env = New()
	test.IsEqualInt64(t, int64(env.DefaultExpiry), day)

	// A value matching no preset snaps down to the longest preset below it.
	os.Setenv("GOKAPI_EXPIRY_OPTIONS", "1h,1d,7d,14d,30d,365d")
	os.Setenv("GOKAPI_DEFAULT_EXPIRY", "10d")
	env = New()
	test.IsEqualInt64(t, int64(env.DefaultExpiry), 7*day)

	// A value shorter than every preset takes the shortest preset instead.
	os.Setenv("GOKAPI_DEFAULT_EXPIRY", "30m")
	env = New()
	test.IsEqualInt64(t, int64(env.DefaultExpiry), hour)

	// Above GOKAPI_MAX_EXPIRY: 14d and up are dropped from the options, so the default snaps
	// down onto 7d, the longest preset that survives.
	os.Setenv("GOKAPI_MAX_EXPIRY", "7d")
	os.Setenv("GOKAPI_DEFAULT_EXPIRY", "30d")
	env = New()
	test.IsEqualInt64(t, int64(env.DefaultExpiry), 7*day)

	// A maximum shorter than every preset empties the option list, which is then restored
	// wholesale, so snapping alone cannot honour the maximum here. The default is clamped to it.
	os.Setenv("GOKAPI_MAX_EXPIRY", "30m")
	os.Setenv("GOKAPI_DEFAULT_EXPIRY", "30d")
	env = New()
	test.IsEqualInt64(t, int64(env.DefaultExpiry), int64(30*time.Minute))

	// 0 does not mean unlimited here, and a negative value is not honoured either: both fall
	// back to 7d, which then snaps onto the 7d preset.
	os.Unsetenv("GOKAPI_MAX_EXPIRY")
	os.Setenv("GOKAPI_DEFAULT_EXPIRY", "0")
	env = New()
	test.IsEqualInt64(t, int64(env.DefaultExpiry), 7*day)
	os.Setenv("GOKAPI_DEFAULT_EXPIRY", "-5d")
	env = New()
	test.IsEqualInt64(t, int64(env.DefaultExpiry), 7*day)

	os.Unsetenv("GOKAPI_DEFAULT_EXPIRY")
	os.Unsetenv("GOKAPI_EXPIRY_OPTIONS")
}

// TestDefaultExpiryIsNotPersistent pins that GOKAPI_DEFAULT_EXPIRY is re-read from the
// environment on every parse, the way GOKAPI_MAX_EXPIRY and GOKAPI_METADATA_RETENTION are,
// instead of being written into the config file on the first start and ignored afterwards.
func TestDefaultExpiryIsNotPersistent(t *testing.T) {
	os.Setenv("GOKAPI_EXPIRY_OPTIONS", "1h,1d,7d,14d,30d,365d")
	os.Setenv("GOKAPI_DEFAULT_EXPIRY", "1d")
	env := New()
	test.IsEqualInt64(t, int64(env.DefaultExpiry), int64(24*time.Hour))
	os.Setenv("GOKAPI_DEFAULT_EXPIRY", "30d")
	env = New()
	test.IsEqualInt64(t, int64(env.DefaultExpiry), int64(30*24*time.Hour))

	field, ok := reflect.TypeOf(Environment{}).FieldByName("DefaultExpiry")
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, field.Tag.Get("persistent"), "")

	os.Unsetenv("GOKAPI_DEFAULT_EXPIRY")
	os.Unsetenv("GOKAPI_EXPIRY_OPTIONS")
}

func TestEncryptionKeyB64(t *testing.T) {
	os.Unsetenv("GOKAPI_ENCRYPTION_KEY_B64")
	env := New()
	test.IsEqualString(t, env.EncryptionKeyB64, "")
	os.Setenv("GOKAPI_ENCRYPTION_KEY_B64", "dGVzdA==")
	env = New()
	test.IsEqualString(t, env.EncryptionKeyB64, "dGVzdA==")
	os.Unsetenv("GOKAPI_ENCRYPTION_KEY_B64")
}

func TestDisableBuiltinUi(t *testing.T) {
	os.Unsetenv("GOKAPI_DISABLE_BUILTIN_UI")
	env := New()
	test.IsEqualBool(t, env.DisableBuiltinUI, false)
	os.Setenv("GOKAPI_DISABLE_BUILTIN_UI", "true")
	env = New()
	test.IsEqualBool(t, env.DisableBuiltinUI, true)
	os.Unsetenv("GOKAPI_DISABLE_BUILTIN_UI")
}

func TestDisableHotlinks(t *testing.T) {
	os.Unsetenv("GOKAPI_DISABLE_HOTLINKS")
	env := New()
	test.IsEqualBool(t, env.DisableHotlinks, false)
	os.Setenv("GOKAPI_DISABLE_HOTLINKS", "true")
	env = New()
	test.IsEqualBool(t, env.DisableHotlinks, true)
	os.Unsetenv("GOKAPI_DISABLE_HOTLINKS")
}

func TestIsAwsProvided(t *testing.T) {
	os.Unsetenv("GOKAPI_AWS_BUCKET")
	os.Unsetenv("GOKAPI_AWS_REGION")
	os.Unsetenv("GOKAPI_AWS_KEY")
	os.Unsetenv("GOKAPI_AWS_KEY_SECRET")
	env := New()
	test.IsEqualBool(t, env.IsAwsProvided(), false)
	os.Setenv("GOKAPI_AWS_BUCKET", "test")
	os.Setenv("GOKAPI_AWS_REGION", "test")
	os.Setenv("GOKAPI_AWS_KEY", "test")
	os.Setenv("GOKAPI_AWS_KEY_SECRET", "test")
	env = New()
	test.IsEqualBool(t, env.IsAwsProvided(), true)
}

func TestGetConfigPaths(t *testing.T) {
	configPath, configDir, configFile, awsConfig := GetConfigPaths()
	test.IsEqualString(t, configPath, "test/test2")
	test.IsEqualString(t, configDir, "test")
	test.IsEqualString(t, configFile, "test2")
	test.IsEqualString(t, awsConfig, "test/cloudconfig.yml")
}
