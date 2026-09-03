package environment

import (
	"fmt"
	"os"
	"path"
	"reflect"
	"sort"
	"strconv"
	"time"

	envParser "github.com/caarlos0/env/v6"
	"github.com/forceu/gokapi/internal/environment/deprecation"
	"github.com/forceu/gokapi/internal/environment/flagparser"
	"github.com/forceu/gokapi/internal/helper"
)

// defaultExpiryOptions mirrors the envDefault tag on Environment.ExpiryOptions. Kept as a
// separate literal, rather than parsed from the tag, so normalizeExpiryOptions has a fallback
// that does not depend on parsing succeeding.
var defaultExpiryOptions = []Duration{
	Duration(time.Hour),
	Duration(24 * time.Hour),
	Duration(7 * 24 * time.Hour),
	Duration(14 * 24 * time.Hour),
	Duration(30 * 24 * time.Hour),
	Duration(365 * 24 * time.Hour),
}

// defaultExpiryFallback is used when GOKAPI_DEFAULT_EXPIRY is unset or not usable. It mirrors
// the envDefault tag on Environment.DefaultExpiry, kept as a separate literal for the same
// reason defaultExpiryOptions is: normalizeDefaultExpiry must have a fallback that does not
// depend on parsing succeeding.
const defaultExpiryFallback = Duration(7 * 24 * time.Hour)

// DefaultPort for the webserver
const DefaultPort = 53842

// MinLengthId is the minimum character length for download and file request IDs
// The value is hardcoded in Environment and needs to be kept in sync with this value.
const MinLengthId = 5

// Environment is a struct containing available env variables
type Environment struct {
	// Sets the directory for the config file
	ConfigDir string `env:"CONFIG_DIR" envDefault:"config"`
	// Sets the name of the config file
	ConfigFile string `env:"CONFIG_FILE" envDefault:"config.json"`
	// The full path to the config file
	ConfigPath string
	// Sets the directory for the data
	DataDir string `env:"DATA_DIR" envDefault:"data" persistent:"true"`
	// Disables the API menu and generation of API keys for non-admin users
	DisableApiMenu bool `env:"DISABLE_API_MENU" envDefault:"false"`
	// Disables the built-in web interface, including the anonymous download and hotlink pages, if set to true.
	// Only the API and the endpoints required by a standalone client remain registered
	DisableBuiltinUI bool `env:"DISABLE_BUILTIN_UI" envDefault:"false"`
	// Disables the CORS check on startup and during setup, if set to true
	DisableCorsCheck bool `env:"DISABLE_CORS_CHECK" envDefault:"false"`
	// Disables automatically adding Docker subnet to trusted proxies, if set to true
	DisableDockerTrustedProxy bool `env:"DISABLE_DOCKER_TRUSTED_PROXY" envDefault:"false"`
	// Sets the size of chunks that are uploaded in MB
	ChunkSizeMB int `env:"CHUNK_SIZE_MB" envDefault:"45" onlyPositive:"true" persistent:"true"`
	// Sets the length of the download IDs
	LengthId int `env:"LENGTH_ID" envDefault:"15" minValue:"5"`
	// Sets the length of the hotlink IDs
	LengthHotlinkId int `env:"LENGTH_HOTLINK_ID" envDefault:"40" minValue:"8"`
	// Also outputs all log file entries to the console output, if set to true
	LogToStdout bool `env:"LOG_STDOUT" envDefault:"false"`
	// Sets the maximum allowed file size in MB
	// Default 102400 = 100GB
	MaxFileSize int `env:"MAX_FILESIZE" envDefault:"102400" onlyPositive:"true" persistent:"true"`
	// Sets the amount of RAM in MB that can be allocated for an upload chunk or file
	// Any chunk or file with a size greater than that will be written to a temporary file
	MaxMemory int `env:"MAX_MEMORY_UPLOAD" envDefault:"50" onlyPositive:"true" persistent:"true"`
	// Sets the furthest expiry allowed for an upload. Any upload that requests a longer
	// expiry, or no expiry at all, is clamped to this value. This applies to every upload
	// path, including file requests, so that no file can be stored permanently. Accepts a
	// Go duration such as "12h", plus "d" (day) and "w" (week) suffixes, e.g. "365d".
	// Set to 0 to allow permanent files. Not persistent: the clamp is re-read from the
	// environment on every use, so it can be raised or lowered without a reconfiguration,
	// but it must therefore be present on every start, the same way production supplies it
	// through deploy config
	MaxExpiry Duration `env:"MAX_EXPIRY" envDefault:"0"`
	// Sets how long a file's metadata record is kept as history after its content is disposed of
	// (expired, downloaded out, or deleted by its owner). Accepts a Go duration such as "12h",
	// plus "d" (day) and "w" (week) suffixes, e.g. "365d". Set to 0 to remove the record together
	// with its content, which is the behaviour prior to this setting existing. Not persistent, for
	// the same reason as GOKAPI_MAX_EXPIRY: storage.CleanUp re-reads it from the environment on
	// every sweep, so it must be present on every start.
	MetadataRetention Duration `env:"METADATA_RETENTION" envDefault:"7d"`
	// Sets how long a file request is kept, together with every file it received and its upload
	// API key, once it has expired or been marked closed. Accepts a Go duration such as "12h",
	// plus "d" (day) and "w" (week) suffixes, e.g. "365d". Set to 0 (default) to disable: nothing
	// is removed just because a request expired or closed, matching the behaviour prior to this
	// setting existing. An operator opts in per instance; upgrading never deletes what an existing
	// install already holds. Not persistent, for the same reason as GOKAPI_MAX_EXPIRY:
	// storage.CleanUp re-reads it from the environment on every sweep, so it must be present on
	// every start.
	FileRequestRetention Duration `env:"FILEREQUEST_RETENTION" envDefault:"0"`
	// Sets how long a download window stays open. A window opens when a request is let through
	// to the bytes and spends one of the resource's download allowance; every further request
	// that arrives before the window closes is served without spending another one, so a broken
	// or resumed transfer does not cost the recipient their download. Access to a resource ends
	// at whichever comes first, its own expiry or the close of its window. Accepts a Go duration
	// such as "30m", plus "d" (day) and "w" (week) suffixes. 0 (default) gives every window zero
	// length, which is the behaviour prior to this setting existing: every request spends an
	// allowance. A negative value is reset to 0. Not persistent, for the same reason as
	// GOKAPI_MAX_EXPIRY: it is re-read from the environment on every use, so it must be present
	// on every start.
	DownloadLeeway Duration `env:"DOWNLOAD_LEEWAY" envDefault:"0" onlyPositive:"true"`
	// Sets the expiry presets a client offers for a new upload, e.g. "1h,1d,7d,14d,30d,365d".
	// Comma separated, same format as GOKAPI_MAX_EXPIRY per entry. An entry that is not
	// positive, a duplicate, or greater than GOKAPI_MAX_EXPIRY is dropped; if that empties
	// the list, the default list above is used instead
	ExpiryOptions []Duration `env:"EXPIRY_OPTIONS" envSeparator:"," envDefault:"1h,1d,7d,14d,30d,365d"`
	// Sets which of the GOKAPI_EXPIRY_OPTIONS presets a client preselects for a new upload,
	// e.g. "7d". Same format as GOKAPI_MAX_EXPIRY. The value is snapped down to the longest
	// preset that does not exceed it, so the preselection is always one of the presets on
	// offer; if no preset is that short, the shortest preset is used. It is also clamped to
	// GOKAPI_MAX_EXPIRY, so the preselection is never a value the server would refuse. A
	// value that is not positive is replaced by the default: unlike elsewhere in Gokapi, 0
	// does not mean unlimited here, because an unlimited default would hand every upload
	// that does not choose otherwise the longest lifetime the instance permits. Not
	// persistent, for the same reason as GOKAPI_MAX_EXPIRY: it is re-read from the
	// environment on every start, so an operator can change the default without a
	// reconfiguration, but it must therefore be present on every start
	DefaultExpiry Duration `env:"DEFAULT_EXPIRY" envDefault:"7d"`
	// Sets the maximum number of files that can be uploaded per file requests created by
	// non-admin users
	// Set to 0 to allow unlimited file count for all users
	MaxFilesGuestUpload int `env:"MAX_FILES_GUESTUPLOAD" envDefault:"100" onlyPositive:"true"`
	// Sets the maximum file size for file requests created by
	// non-admin users
	// Set to 0 to allow files with a size of up to a value set with GOKAPI_MAX_FILESIZE
	// for all users
	// Default 10240 = 10GB
	MaxSizeGuestUploadMb int `env:"MAX_SIZE_GUESTUPLOAD" envDefault:"10240" onlyPositive:"true"`
	// Set the number of chunks that are uploaded in parallel for a single file
	MaxParallelUploads int `env:"MAX_PARALLEL_UPLOADS" envDefault:"3" onlyPositive:"true" persistent:"true"`
	// Sets the minimum free space on the disk in MB for accepting an upload
	MinFreeSpaceMB int `env:"MIN_FREE_SPACE" envDefault:"400" onlyPositive:"true"`
	// Sets the minimum password length. Regardless of this value, every password
	// must also contain a lowercase letter, an uppercase letter, a number and a special character
	MinLengthPassword int `env:"MIN_LENGTH_PASSWORD" envDefault:"8" minValue:"6"`
	// Allows all users by default to create file requests, if set to true
	PermRequestGrantedByDefault bool `env:"GUEST_UPLOAD_BY_DEFAULT" envDefault:"false"`
	// Sets the number of days after which an admin or password-protected-file session
	// expires and needs to be renewed by logging in again. Does not apply to sessions
	// created through OAuth2, which are instead bound to the recheck interval configured
	// in the admin menu
	SessionDurationDays int `env:"SESSION_DURATION_DAYS" envDefault:"7" minValue:"1"`
	// Sets a list of trusted proxies. If set, the webserver will trust the IP addresses sent
	// by these proxies with the X-Forwarded-For and X-REAL-IP header
	// List is comma separated; entries can be fixed IPs ("10.0.0.1, 10.0.0.2")
	// and subnets ("10.0.0.0/24")
	TrustedProxies []string `env:"TRUSTED_PROXIES" envSeparator:"," envDefault:"127.0.0.1"`
	// Set this to true if you are using Cloudflare
	UseCloudFlare bool `env:"USE_CLOUDFLARE" envDefault:"false"`
	// Sets the webserver port
	WebserverPort int `env:"PORT" envDefault:"53842" onlyPositive:"true" persistent:"true"`
	// Allow hotlinking of videos. Note: Due to buffering, playing a video might count as
	// multiple downloads. It is only recommended to use video hotlinking for uploads with
	// unlimited downloads enabled
	HotlinkVideos bool `env:"ENABLE_HOTLINK_VIDEOS" envDefault:"false"`
	// Disables the creation of hotlinks, if set to true. Existing hotlinks are purged on startup,
	// so that no password-free URL keeps serving a file after this is enabled
	DisableHotlinks bool `env:"DISABLE_HOTLINKS" envDefault:"false"`
	// Sets the master encryption key, encoded as base64 of exactly 32 raw bytes, e.g. supplied
	// by an external secret store. If set, the key is used instead of the cipher stored in the
	// config file and setup does not persist a cipher. May only be set if the encryption level
	// uses a stored key
	EncryptionKeyB64 string `env:"ENCRYPTION_KEY_B64"`
	// Sets the AWS bucket name
	AwsBucket string `env:"AWS_BUCKET"`
	// Sets the AWS region name
	AwsRegion string `env:"AWS_REGION"`
	// Sets the AWS API key
	AwsKeyId string `env:"AWS_KEY"`
	// Sets the AWS API secret
	AwsKeySecret string `env:"AWS_KEY_SECRET"`
	// Sets the AWS endpoint
	AwsEndpoint string `env:"AWS_ENDPOINT"`
	// Proxies downloads through the server instead of redirecting to pre-signed S3 URLs, if set to true
	AwsProxyDownload bool `env:"AWS_PROXY_DOWNLOAD" envDefault:"false"`
	// List of active deprecations
	ActiveDeprecations []deprecation.Deprecation
	isSet              bool
}

// IsParsed returns true if the env variables have been parsed
func (e *Environment) IsParsed() bool {
	return e.isSet
}

// New parses the env variables
func New() Environment {
	result := Environment{
		WebserverPort: DefaultPort,
		isSet:         true,
	}

	result = parseEnvVars(result)
	err := enforceIntLimits(&result)
	if err != nil {
		fmt.Println("Error parsing env variables:", err)
		osExit(1)
	}
	result = parseFlags(result)
	normalizeExpiryOptions(&result)
	normalizeDefaultExpiry(&result)
	result.ActiveDeprecations = deprecation.GetActive()

	return result
}

// normalizeExpiryOptions cleans up ExpiryOptions. enforceIntLimits only understands
// reflect.Int* kinds (see its switch below) and silently skips slices and custom types, so
// its onlyPositive handling never applies to a []Duration - this is the dedicated pass for it.
// Options are de-duplicated and sorted ascending so a client always sees a clean, ordered
// picker. An option above MaxExpiry is dropped rather than clamped: clamping it would leave
// two presets that silently resolve to the same value, which is more confusing than one
// fewer preset. If dropping empties the list entirely, e.g. because MaxExpiry is lower than
// every configured option, the upstream default list is used instead - a broken config must
// never leave a client with no options at all.
func normalizeExpiryOptions(result *Environment) {
	seen := make(map[Duration]bool, len(result.ExpiryOptions))
	options := make([]Duration, 0, len(result.ExpiryOptions))
	for _, opt := range result.ExpiryOptions {
		if opt <= 0 || seen[opt] {
			continue
		}
		if result.MaxExpiry > 0 && opt > result.MaxExpiry {
			fmt.Printf("Warning: GOKAPI_EXPIRY_OPTIONS contains %s, which is greater than GOKAPI_MAX_EXPIRY and was dropped\n", time.Duration(opt))
			continue
		}
		seen[opt] = true
		options = append(options, opt)
	}
	sort.Slice(options, func(i, j int) bool { return options[i] < options[j] })
	if len(options) == 0 {
		options = append([]Duration{}, defaultExpiryOptions...)
	}
	result.ExpiryOptions = options
}

// normalizeDefaultExpiry pins DefaultExpiry to a value a client can select and the server will
// then accept. It runs after normalizeExpiryOptions, so ExpiryOptions is already de-duplicated,
// sorted ascending and never empty.
//
// A value of 0 or less is replaced by defaultExpiryFallback rather than rejected: a typo in
// deploy config must not take an instance down, and there is a safe value to fall back to.
//
// The value is then snapped down to the longest option that does not exceed it. A default
// matching no option would leave a client preselecting a value none of its presets offer, and
// snapping down rather than up keeps the failure direction safe - the result is never longer
// than what was configured. If no option is that short, the shortest option is used, which is
// the safe direction again.
//
// Snapping to an option usually satisfies MaxExpiry on its own, because normalizeExpiryOptions
// has already dropped every option above it. The exception is a maximum shorter than every
// configured option, where that pass restores the full built-in option list instead of leaving
// a client with none; the final clamp covers that case.
func normalizeDefaultExpiry(result *Environment) {
	if result.DefaultExpiry <= 0 {
		fmt.Printf("Warning: GOKAPI_DEFAULT_EXPIRY must be positive, %s is used instead\n", time.Duration(defaultExpiryFallback))
		result.DefaultExpiry = defaultExpiryFallback
	}
	selected := result.ExpiryOptions[0]
	for _, opt := range result.ExpiryOptions {
		if opt <= result.DefaultExpiry {
			selected = opt
		}
	}
	result.DefaultExpiry = selected
	if result.MaxExpiry > 0 && result.DefaultExpiry > result.MaxExpiry {
		result.DefaultExpiry = result.MaxExpiry
	}
}

func parseEnvVars(result Environment) Environment {
	err := envParser.Parse(&result, envParser.Options{
		Prefix: "GOKAPI_",
	})
	if err != nil {
		fmt.Println("Error parsing env variables:", err)
		osExit(1)
		return Environment{}
	}
	return result
}

func enforceIntLimits(result *Environment) error {
	v := reflect.ValueOf(result)
	if v.Kind() != reflect.Ptr || v.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("env must be a pointer to a struct")
	}

	v = v.Elem()
	t := v.Type()

	for i := 0; i < v.NumField(); i++ {
		fieldVal := v.Field(i)
		fieldType := t.Field(i)

		checkForPositive := fieldType.Tag.Get("onlyPositive") != ""
		checkForMinValue := fieldType.Tag.Get("minValue") != ""

		if !checkForPositive && !checkForMinValue {
			continue
		}

		// Only handle signed integers
		switch fieldVal.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:

			if checkForMinValue {
				valStr := fieldType.Tag.Get("minValue")
				minVal, err := strconv.ParseInt(valStr, 10, fieldVal.Type().Bits())
				if err != nil {
					return fmt.Errorf("invalid minValue for field %s: %w", fieldType.Name, err)
				}
				if fieldVal.Int() < minVal {
					if fieldVal.CanSet() {
						fieldVal.SetInt(minVal)
					} else {
						return fmt.Errorf("cannot set fieldval %s", fieldType.Name)
					}
					continue
				}
			}

			if !checkForPositive {
				continue
			}
			if fieldVal.Int() >= 0 {
				continue
			}

			defaultStr := fieldType.Tag.Get("envDefault")
			defaultVal, err := strconv.ParseInt(defaultStr, 10, fieldVal.Type().Bits())
			if err != nil {
				return fmt.Errorf("invalid envDefault for field %s: %w", fieldType.Name, err)
			}

			if fieldVal.CanSet() {
				fieldVal.SetInt(defaultVal)
			} else {
				return fmt.Errorf("cannot set fieldval %s", fieldType.Name)
			}
		default:
			continue
		}
	}
	return nil
}

func parseFlags(result Environment) Environment {
	flags := flagparser.ParseFlags()
	if flags.IsPortSet {
		if flags.Port < 1 {
			flags.Port = DefaultPort
		}
		result.WebserverPort = flags.Port
	}
	if flags.IsConfigDirSet {
		result.ConfigDir = flags.ConfigDir
	}
	if flags.IsDataDirSet {
		result.DataDir = flags.DataDir
	}

	result.ConfigDir = path.Clean(result.ConfigDir)
	result.DataDir = path.Clean(result.DataDir)
	result.ConfigPath = result.ConfigDir + "/" + result.ConfigFile
	if flags.IsConfigPathSet {
		result.ConfigPath = flags.ConfigPath
	}

	if IsDockerInstance() && os.Getenv("TMPDIR") == "" {
		err := os.Setenv("TMPDIR", result.DataDir)
		helper.Check(err)
	}
	if result.LengthId < 5 {
		result.LengthId = 5
	}
	if result.LengthHotlinkId < 8 {
		result.LengthHotlinkId = 8
	}
	if result.MaxMemory < 5 {
		result.MaxMemory = 5
	}
	if result.MaxFileSize < 1 {
		result.MaxFileSize = 5
	}
	if result.MinLengthPassword < 6 {
		result.MinLengthPassword = 6
	}
	return result
}

// IsAwsProvided returns true if all required env variables have been set for using AWS S3 / Backblaze
func (e *Environment) IsAwsProvided() bool {
	return e.AwsBucket != "" &&
		e.AwsRegion != "" &&
		e.AwsKeyId != "" &&
		e.AwsKeySecret != ""
}

// GetConfigPaths returns the config paths to config files and the directory containing the files. The following results are returned:
// Path to config file, Path to directory containing config file, Name of config file, Path to AWS config file
func GetConfigPaths() (pathConfigFile, pathConfigDir, nameConfigFile, pathAwsConfig string) {
	env := New()
	pathAwsConfig = env.ConfigDir + "/cloudconfig.yml"
	return env.ConfigPath, env.ConfigDir, env.ConfigFile, pathAwsConfig
}

var osExit = os.Exit
