package configuration

/**
Loading and saving of the persistent configuration
*/

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"

	"github.com/forceu/gokapi/internal/configuration/cloudconfig"
	"github.com/forceu/gokapi/internal/configuration/configupgrade"
	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/environment"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/logging"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/storage/filesystem"
	"golang.org/x/crypto/argon2"
)

// parsedEnvironment is an object containing the environment variables
var parsedEnvironment environment.Environment

// ServerSettings is an object containing the server configuration
var serverSettings models.Configuration

var usesHttps bool

// Exists returns true if configuration files are present
func Exists() bool {
	configPath, _, _, _ := environment.GetConfigPaths()
	exists, err := helper.FileExists(configPath)
	helper.Check(err)
	return exists
}

// loadFromFile parses the given file and adds salts, if they are invalid
func loadFromFile(path string) (models.Configuration, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return models.Configuration{}, err
	}
	settings := models.Configuration{}
	if err = json.Unmarshal(raw, &settings); err != nil {
		return models.Configuration{}, err
	}
	if len(settings.Authentication.SaltFiles) < 20 {
		settings.Authentication.SaltFiles = helper.GenerateRandomString(30)
		fmt.Println("Warning: Salt for file hash invalid, generating new salt")
	}
	if len(settings.Authentication.SaltAdmin) < 20 {
		settings.Authentication.SaltAdmin = helper.GenerateRandomString(30)
		if settings.Authentication.Method == 0 { // == authentication.Internal, but would create import cycle
			fmt.Println("Warning: Salt for admin password invalid, generating new salt. You will need to reset the admin password.")
		}
	}
	normalizeOnlyRegisteredUsers(&settings)
	return settings, nil
}

// normalizeOnlyRegisteredUsers unconditionally forces OnlyRegisteredUsers to true whenever hybrid
// auth (internal method with OAuth enabled alongside it) is on. The setup wizard already defaults
// this the same way, in the hybrid branch that builds the authentication settings, but hybrid
// mode can currently only be turned on by hand-editing config.json, which never goes through the
// wizard. Every config.json Gokapi
// has ever written already contains an explicit "OnlyRegisteredUsers" key (models.Configuration
// has no omitempty on that field), so a "was the key present" check can never distinguish a
// hand-edited hybrid config from a normal one - it must always be forced instead. An operator who
// truly wants self-registration for any Google account must use a distinct, deliberately
// dangerous opt-in (see AllowHybridSelfRegistration).
func normalizeOnlyRegisteredUsers(settings *models.Configuration) {
	if settings.Authentication.Method != models.AuthenticationInternal || !settings.Authentication.OAuthEnabledAlongsideInternal {
		return
	}
	if settings.Authentication.AllowHybridSelfRegistration {
		return
	}
	settings.Authentication.OnlyRegisteredUsers = true
}

// Load loads the configuration or creates the folder structure and a default configuration
func Load() {
	parsedEnvironment = environment.New()
	// No check if file exists, as this was checked earlier
	settings, err := loadFromFile(parsedEnvironment.ConfigPath)
	helper.Check(err)
	serverSettings = settings
	usesHttps = strings.HasPrefix(strings.ToLower(serverSettings.ServerUrl), "https://")

	if configupgrade.DoUpgrade(&serverSettings, &parsedEnvironment) {
		save()
	}
	if serverSettings.PublicName == "" {
		serverSettings.PublicName = "Gokapi"
	}
	if serverSettings.MaxParallelUploads == 0 {
		serverSettings.MaxParallelUploads = 4
	}
	if serverSettings.ChunkSize == 0 {
		serverSettings.ChunkSize = 45
	}
	// Generated here rather than in a configupgrade step so that a fresh setup, an upgrade from
	// any older version and a config someone hand-edited the key out of are all covered by one
	// path. Length is checked rather than emptiness: a truncated key would otherwise be kept and
	// silently weaken every token signed with it.
	if len(serverSettings.DownloadSessionKey) < 32 {
		serverSettings.DownloadSessionKey = helper.GenerateRandomString(48)
		save()
	}
	helper.CreateDir(serverSettings.DataDir)
	filesystem.Init(serverSettings.DataDir)
	logging.Init(serverSettings.DataDir)
}

// ConnectDatabase loads the database that is defined in the configuration
func ConnectDatabase() {
	dbConfig, err := database.ParseUrl(serverSettings.DatabaseUrl, false)
	helper.Check(err)
	database.Connect(dbConfig)
	database.Upgrade()
}

// UsesHttps returns true if Gokapi URL is set to a secure URL
func UsesHttps() bool {
	return usesHttps
}

// Get returns a pointer to the server configuration
func Get() *models.Configuration {
	return &serverSettings
}

// Save the configuration as a json file
func save() {
	file, err := os.OpenFile(parsedEnvironment.ConfigPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Println("Error writing configuration:", err)
		os.Exit(1)
	}
	defer file.Close()

	_, err = io.Copy(file, bytes.NewReader(serverSettings.ToJson()))
	if err != nil {
		fmt.Println("Error writing configuration:", err)
		os.Exit(1)
	}
}

// LoadFromSetup creates a new configuration file after a user completed the setup. If cloudConfig is not nil, a new
// cloud config file is created. If it is nil an existing cloud config file will be deleted.
func LoadFromSetup(config models.Configuration, cloudConfig *cloudconfig.CloudConfig, e2eConfig End2EndReconfigParameters, passwordHash string) {
	parsedEnvironment = environment.New()
	helper.CreateDir(parsedEnvironment.ConfigDir)

	serverSettings = config
	if cloudConfig != nil {
		err := cloudconfig.Write(*cloudConfig)
		if err != nil {
			fmt.Println("Error writing cloud configuration:", err)
			os.Exit(1)
		}
	} else {
		err := cloudconfig.Delete()
		if err != nil {
			fmt.Println("Error deleting cloud configuration:", err)
			os.Exit(1)
		}
	}
	save()
	Load()
	ConnectDatabase()
	err := database.EditSuperAdmin(serverSettings.Authentication.Username, passwordHash)
	if err != nil {
		fmt.Println("Could not edit superadmin, as none was found, but other users were present.")
		os.Exit(1)
	}
	database.DeleteAllSessions()
	if e2eConfig.DeleteEnd2EndEncryption {
		for _, user := range database.GetAllUsers() {
			database.DeleteEnd2EndInfo(user.Id)
		}
	}
	if e2eConfig.DeleteEncryptedStorage {
		deleteAllEncryptedStorage()
	}
}

// GetEnvironment returns a copy of the environment object
func GetEnvironment() environment.Environment {
	if !parsedEnvironment.IsParsed() {
		panic("Environment is not parsed yet")
	}
	return parsedEnvironment
}

func deleteAllEncryptedStorage() {
	files := database.GetAllMetadata()
	for _, file := range files {
		if file.Encryption.IsEncrypted {
			file.UnlimitedTime = false
			file.ExpireAt = 0
			database.SaveMetaData(file)
		}
	}
}

// SetDeploymentPassword sets a new password. This should only be used for non-interactive deployment but is not enforced
func SetDeploymentPassword(newPassword string) {
	if len(newPassword) < parsedEnvironment.MinLengthPassword {
		fmt.Printf("Password needs to be at least %d characters long\n", parsedEnvironment.MinLengthPassword)
		os.Exit(1)
	}
	err := ValidatePasswordComplexity(newPassword)
	if err != nil {
		fmt.Println("Password needs a lowercase letter, an uppercase letter, a number and a special character")
		os.Exit(1)
	}
	serverSettings.Authentication.SaltAdmin = helper.GenerateRandomString(30)
	err = database.EditSuperAdmin(serverSettings.Authentication.Username, HashPassword(newPassword, false, ""))
	if err != nil {
		fmt.Println("No super-admin user found, but database contains other users. Aborting.")
		os.Exit(1)
	}
	user, _ := database.GetSuperAdmin()
	database.DeleteAllSessionsByUser(user.Id)
	save()
	fmt.Println("New password has been set successfully for user " + serverSettings.Authentication.Username + ".")
	os.Exit(0)
}

// Deprecated: SHA1 is not secure, this is only used for migrating
// passwords from <v2.2.5 to the current version
// Will be removed soon.
func hashSha1(password, salt string) string {
	pwBytes := []byte(password + salt)
	hash := sha1.New()
	hash.Write(pwBytes)
	return hex.EncodeToString(hash.Sum(nil))
}

const (
	argonTime    = 2
	argonMemory  = 28 * 1024 // 28 MB
	argonThreads = 1
	argonKeyLen  = 32
	argonSaltLen = 16
)

// HashPassword hashes a password with Argon2id.
// useOldHash is used for migrating from <v2.2.5 to the current version
// Will be removed soon.
// legacySalt is only used for migrating from <v2.2.5 to the current version
func HashPassword(password string, useOldHash bool, legacySalt string) string {
	if password == "" {
		return ""
	}
	pwBytes := []byte(password + legacySalt)
	if useOldHash {
		if legacySalt == "" {
			panic(errors.New("no salt provided for legacy hash"))
		}
		hash := sha1.New()
		hash.Write(pwBytes)
		return hex.EncodeToString(hash.Sum(nil))
	}
	// Argon2id: generate a fresh random salt, ignore the global salt
	randomSalt := []byte(helper.GenerateRandomString(argonSaltLen))
	hash := argon2.IDKey(
		[]byte(password),
		randomSalt,
		argonTime,
		argonMemory,
		argonThreads,
		argonKeyLen,
	)

	return fmt.Sprintf("argon2id$%s$%s",
		hex.EncodeToString(randomSalt),
		hex.EncodeToString(hash),
	)
}

// ErrSharePasswordTooShort is returned by ValidateSharePassword when a caller supplies a
// password intended to protect a share, but after trimming leading and trailing
// whitespace it is shorter than the server-side minimum (env.MinLengthPassword).
var ErrSharePasswordTooShort = errors.New("password does not meet the minimum length requirement")

// ErrPasswordTooSimple is returned by ValidatePasswordComplexity when a password is long
// enough but does not use all four required character classes.
var ErrPasswordTooSimple = errors.New("password does not meet the complexity requirement")

// ValidatePasswordComplexity checks that a password contains at least one lowercase
// letter, one uppercase letter, one digit and one character that is none of those. It is
// applied on top of the minimum length, not instead of it.
//
// A share password is the only thing standing between a stored file and anyone who has
// the link, and the link is routinely forwarded further than the sender intended. Length
// alone leaves "password" acceptable at the default minimum of 8.
//
// The fourth class is defined as "not a letter and not a digit" rather than as a list of
// permitted punctuation, so a password typed on a non-US keyboard is not rejected for
// using a symbol that did not occur to us.
func ValidatePasswordComplexity(password string) error {
	var hasLower, hasUpper, hasDigit, hasSpecial bool
	for _, char := range password {
		if unicode.IsLower(char) {
			hasLower = true
		} else if unicode.IsUpper(char) {
			hasUpper = true
		} else if unicode.IsDigit(char) {
			hasDigit = true
		} else {
			hasSpecial = true
		}
	}
	if !hasLower {
		return fmt.Errorf("%w: needs a lowercase letter", ErrPasswordTooSimple)
	}
	if !hasUpper {
		return fmt.Errorf("%w: needs an uppercase letter", ErrPasswordTooSimple)
	}
	if !hasDigit {
		return fmt.Errorf("%w: needs a number", ErrPasswordTooSimple)
	}
	if !hasSpecial {
		return fmt.Errorf("%w: needs a special character", ErrPasswordTooSimple)
	}
	return nil
}

// ValidateSharePassword enforces the server-side minimum length on a password a caller
// wants to use to protect a share (an uploaded file or a bundle). This is the single
// choke point every path that sets a share's PasswordHash must call before hashing, so
// that no client - whatever it trims, strips or forgets to validate - can end up
// publishing a file that is supposed to be password protected but isn't.
//
// isPresent must reflect whether the caller actually supplied a password value, not
// merely whether the resulting string is non-empty. This distinction matters because
// Go's HTTP header parser silently trims a whitespace-only header value down to "" before
// application code ever sees it, which would otherwise make a password of three spaces
// indistinguishable from no password being supplied at all - the exact bypass this
// function exists to close. Callers reading a header-based parameter must pass whether
// the header was present in the request (e.g. the generated parser's foundHeaders bit),
// not password != "". Callers reading a raw form field, where whitespace is not trimmed
// by the transport, may use password != "" instead.
//
// When isPresent is false, ("", nil) is returned: no password was requested, which is
// the ordinary and completely legitimate default for most uploads. When isPresent is
// true, the value is trimmed and, if the result is shorter than MinLengthPassword -
// including an empty or whitespace-only submission - ErrSharePasswordTooShort is
// returned so the caller can reject the request with a clear error instead of silently
// storing an empty password hash. On success the trimmed password is returned; callers
// should hash that value, not the original, so a value that only differs by leading or
// trailing whitespace does not produce a hash the visitor typing it back verbatim can
// never satisfy.
func ValidateSharePassword(password string, isPresent bool) (string, error) {
	if !isPresent {
		return "", nil
	}
	trimmed := strings.TrimSpace(password)
	minLength := GetEnvironment().MinLengthPassword
	if len(trimmed) < minLength {
		return "", fmt.Errorf("%w: minimum length is %d characters", ErrSharePasswordTooShort, minLength)
	}
	err := ValidatePasswordComplexity(trimmed)
	if err != nil {
		return "", err
	}
	return trimmed, nil
}

// VerifyPassword checks a plaintext password against a stored hash.
// If hash is still SHA1, it will check the sha1 hash and return the second parameter as true, to indicate
// that the hash was generated with the old hash function and requires rehashing
// Oherwise argon2 will be used and the second parameter will be false
func VerifyPassword(password, storedHash, legacySalt string) (bool, bool) {
	if len(storedHash) == 40 {
		hashedPassword := hashSha1(password, legacySalt)
		return helper.IsEqualStringConstantTime(hashedPassword, storedHash), true
	}

	parts := strings.Split(storedHash, "$")
	if len(parts) != 3 || parts[0] != "argon2id" {
		return false, false
	}

	salt, err := hex.DecodeString(parts[1])
	if err != nil {
		return false, false
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		argonTime,
		argonMemory,
		argonThreads,
		argonKeyLen,
	)
	hashedPassword := hex.EncodeToString(hash)
	return helper.IsEqualStringConstantTime(hashedPassword, parts[2]), false
}

// End2EndReconfigParameters contains values on how to reset E2E, if requested
type End2EndReconfigParameters struct {
	DeleteEnd2EndEncryption bool
	DeleteEncryptedStorage  bool
}
