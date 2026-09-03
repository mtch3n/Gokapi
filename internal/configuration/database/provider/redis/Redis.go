package redis

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/forceu/gokapi/internal/environment"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
	redigo "github.com/gomodule/redigo/redis"
)

// DatabaseProvider contains the database instance
type DatabaseProvider struct {
	pool     *redigo.Pool
	dbPrefix string
}

// DatabaseSchemeVersion contains the version number to be expected from the current database. If lower, an upgrade will be performed
const DatabaseSchemeVersion = 12

// New returns an instance
func New(dbConfig models.DbConnection) (DatabaseProvider, error) {
	return DatabaseProvider{}.init(dbConfig)
}

// GetType returns 1, for being a Redis interface
func (p DatabaseProvider) GetType() int {
	return 1 // dbabstraction.Redis
}

// Init connects to the database and creates the table structure, if necessary
// IMPORTANT: The function returns itself, as Go does not allow this function to be pointer-based
// The resulting new reference must then be used.
func (p DatabaseProvider) init(config models.DbConnection) (DatabaseProvider, error) {
	if config.HostUrl == "" {
		return DatabaseProvider{}, errors.New("empty database url was provided")
	}
	p.dbPrefix = config.RedisPrefix
	p.pool = newPool(config)
	conn := p.pool.Get()
	defer conn.Close()
	_, err := redigo.String(conn.Do("PING"))
	if err != nil {
		return DatabaseProvider{}, err
	}
	isPersistenceEnabled, err := p.isPersistenceEnabled()
	if err == nil {
		if !isPersistenceEnabled {
			fmt.Println("WARNING! Redis persistence is disabled. ALL DATA WILL BE LOST after a database restart.")
		}
	} else {
		fmt.Println("Unable to check if Redis has persistence enabled.")
	}

	// If DB version is 0, the DB is new and therefore set version to latest one.
	// Otherwise, Upgrade() would be called after loading
	if p.GetDbVersion() == 0 {
		p.SetDbVersion(DatabaseSchemeVersion)
	}
	return p, nil
}

func (p DatabaseProvider) isPersistenceEnabled() (bool, error) {
	output, err := redigo.Values(p.getConfigRaw("save"))
	if err != nil {
		return false, err
	}
	if len(output) < 2 {
		return false, nil
	}
	saveVal, _ := redigo.String(output[1], nil)
	return len(saveVal) > 0, nil
}

func getDialOptions(config models.DbConnection) []redigo.DialOption {
	dialOptions := []redigo.DialOption{redigo.DialClientName("gokapi")}
	if config.Username != "" {
		dialOptions = append(dialOptions, redigo.DialUsername(config.Username))
	}
	if config.Password != "" {
		dialOptions = append(dialOptions, redigo.DialPassword(config.Password))
	}
	if config.RedisUseSsl {
		dialOptions = append(dialOptions, redigo.DialUseTLS(true))
	}
	return dialOptions
}

func newPool(config models.DbConnection) *redigo.Pool {

	newRedisPool := &redigo.Pool{
		MaxIdle:     10,
		IdleTimeout: 2 * time.Minute,

		Dial: func() (redigo.Conn, error) {
			c, err := redigo.Dial("tcp", config.HostUrl, getDialOptions(config)...)
			if err != nil {
				fmt.Println("Error connecting to redis")
			}
			helper.Check(err)
			return c, err
		},

		TestOnBorrow: func(c redigo.Conn, t time.Time) error {
			_, err := c.Do("PING")
			return err
		},
	}
	return newRedisPool
}

// Upgrade migrates the DB to a new Gokapi version, if required
func (p DatabaseProvider) Upgrade(currentDbVersion int) {
	// < v2.0.0
	if currentDbVersion < 5 {
		fmt.Println("Error: Gokapi runs >=v2.0.0, but Database is <v2.0.0. Please update to v2.0.0 first.")
		osExit(1)
		return
	}
	// < v2.2.0
	if currentDbVersion < 6 {
		grantUploadPerm := environment.New().PermRequestGrantedByDefault
		for _, user := range p.GetAllUsers() {
			if grantUploadPerm || user.IsAdmin() {
				user.GrantPermission(models.UserPermGuestUploads)
				p.SaveUser(user, false)
			}
		}
		for _, apiKey := range p.GetAllApiKeys() {
			if apiKey.IsSystemKey {
				p.DeleteApiKey(apiKey.Id)
			}
		}
	}
	// < v2.2.3
	if currentDbVersion < 7 {
		// Remove all hotlinks for SVG files
		for _, hotlink := range p.GetAllHotlinks() {
			fileId, ok := p.GetHotlink(hotlink)
			if !ok {
				p.DeleteHotlink(hotlink)
				continue
			}
			file, ok := p.GetMetaDataById(fileId)
			if !ok {
				p.DeleteHotlink(hotlink)
				continue
			}
			if strings.HasSuffix(strings.ToLower(file.Name), ".svg") || strings.HasPrefix(strings.ToLower(file.ContentType), "image/svg") {
				p.DeleteHotlink(hotlink)
				file.HotlinkId = ""
				p.SaveMetaData(file)
			}
		}
	}
	// < v2.2.5
	if currentDbVersion < 8 {
		p.DeleteAllSessions()
	}
	// < v2.4.0 (hybrid auth support)
	// Redis has no ADD COLUMN with a DEFAULT: a user hash written before AuthProvider existed
	// simply lacks that field, and redigo.ScanStruct returns the zero value (empty string) for
	// it - the exact value that the account-takeover allow-list in
	// webserver/authentication.getOrCreateUser treats as "not provisioned for OIDC, but also not
	// yet backfilled". Every existing user is rewritten here with AuthProvider explicitly set to
	// "internal" so that guard has something correct to compare against.
	if currentDbVersion < 9 {
		for _, user := range p.GetAllUsers() {
			if user.AuthProvider == "" {
				user.AuthProvider = models.AuthProviderInternal
				p.SaveUser(user, false)
			}
		}
	}
	// < v2.4.1
	// Persists which auth method created a session, so a renewal recreates the same kind of
	// session (see sessionmanager.useSession) instead of inferring it from the current global
	// auth method - which is wrong in hybrid mode. Redis has no ADD COLUMN with a DEFAULT: a
	// session hash written before IsOauth existed simply lacks that field, and
	// redigo.ScanStruct returns the zero value (false) for it. Without wiping sessions here, a
	// pre-v10 OAuth session would silently renew as a password session from now on, skipping the
	// OAuthRecheckInterval that is supposed to re-verify its group membership on every renewal.
	// The last DeleteAllSessions in this ladder was at v8, so any session created between v8 and
	// v10 would otherwise straddle this schema change with no valid IsOauth value.
	if currentDbVersion < 10 {
		p.DeleteAllSessions()
	}
	// The folder as the unit of sharing: PasswordHash, ExpireAt, UnlimitedTime, DownloadsRemaining
	// and UnlimitedDownloads move from being inferred off member files onto FileBundles itself.
	// Redis has no ADD COLUMN with a DEFAULT: a bundle hash written before these fields existed
	// simply lacks them, and redigo.ScanStruct returns their zero value - the same "unprotected,
	// no downloads left" state a fresh, uninitialised bundle would report. Unlike a plain
	// zero-value read, though, every existing bundle needs an explicit write here: the correct
	// value for most of these fields is derived from its current members
	// (models.DeriveBundleSettingsFromMembers), not simply "whatever the zero value happens to
	// mean", so this backfill has to run once and touch every bundle rather than being left to
	// happen lazily on the first save.
	if currentDbVersion < 11 {
		p.backfillBundleSettingsFromMembers()
	}
}

// backfillBundleSettingsFromMembers derives every existing bundle's PasswordHash, ExpireAt,
// UnlimitedTime, DownloadsRemaining and UnlimitedDownloads from its current members and writes
// them - see models.DeriveBundleSettingsFromMembers for the merge rule. Deterministic in its
// members, so re-running this reproduces the same values rather than drifting.
func (p DatabaseProvider) backfillBundleSettingsFromMembers() {
	allFiles := p.GetAllMetadata()
	membersByBundle := make(map[string][]models.File)
	for _, file := range allFiles {
		if file.BundleId == "" {
			continue
		}
		if !file.IsBundleMember(file.BundleId) {
			continue
		}
		membersByBundle[file.BundleId] = append(membersByBundle[file.BundleId], file)
	}
	for _, bundle := range p.GetAllFileBundles() {
		passwordHash, expireAt, unlimitedTime, downloadsRemaining, unlimitedDownloads :=
			models.DeriveBundleSettingsFromMembers(membersByBundle[bundle.Id])
		bundle.PasswordHash = passwordHash
		bundle.ExpireAt = expireAt
		bundle.UnlimitedTime = unlimitedTime
		bundle.DownloadsRemaining = downloadsRemaining
		bundle.UnlimitedDownloads = unlimitedDownloads
		p.SaveFileBundle(bundle)
	}
}

const keyDbVersion = "dbversion"

// GetDbVersion gets the version number of the database
func (p DatabaseProvider) GetDbVersion() int {
	key, _ := p.getKeyInt(keyDbVersion)
	return key
}

// SetDbVersion sets the version number of the database
func (p DatabaseProvider) SetDbVersion(currentVersion int) {
	p.setKey(keyDbVersion, currentVersion)
}

// GetSchemaVersion returns the version number that the database should be if fully upgraded
func (p DatabaseProvider) GetSchemaVersion() int {
	return DatabaseSchemeVersion
}

// Close the database connection
func (p DatabaseProvider) Close() {
	err := p.pool.Close()
	if err != nil {
		fmt.Println(err)
	}
}

// RunGarbageCollection runs the database GC
func (p DatabaseProvider) RunGarbageCollection() {
	// No cleanup required
}

// Function to get all hashmaps with a given prefix
func (p DatabaseProvider) getAllValuesWithPrefix(prefix string) map[string]any {
	result := make(map[string]any)
	allKeys := p.getAllKeysWithPrefix(prefix)
	for _, key := range allKeys {
		value, err := p.getKeyRaw(key)
		if errors.Is(err, redigo.ErrNil) {
			continue
		}
		helper.Check(err)
		result[key] = value
	}
	return result
}

// Function to get all hashmaps with a given prefix
func (p DatabaseProvider) getAllHashesWithPrefix(prefix string) map[string][]any {
	result := make(map[string][]any)
	allKeys := p.getAllKeysWithPrefix(prefix)
	for _, key := range allKeys {
		hashMap, ok := p.getHashMap(key)
		if !ok {
			continue
		}
		result[key] = hashMap
	}
	return result
}

func (p DatabaseProvider) getAllKeysWithPrefix(prefix string) []string {
	var result []string
	conn := p.pool.Get()
	defer conn.Close()
	fullPrefix := p.dbPrefix + prefix
	cursor := 0
	for {
		reply, err := redigo.Values(conn.Do("SCAN", cursor, "MATCH", fullPrefix+"*", "COUNT", 100))
		helper.Check(err)

		cursor, _ = redigo.Int(reply[0], nil)
		keys, _ := redigo.Strings(reply[1], nil)
		for _, key := range keys {
			result = append(result, strings.Replace(key, p.dbPrefix, "", 1))
		}
		if cursor == 0 {
			break
		}
	}
	return result
}

func (p DatabaseProvider) setKey(id string, content any) {
	conn := p.pool.Get()
	defer conn.Close()
	_, err := conn.Do("SET", p.dbPrefix+id, content)
	helper.Check(err)
}

func (p DatabaseProvider) getKeyRaw(id string) (any, error) {
	conn := p.pool.Get()
	defer conn.Close()
	return conn.Do("GET", p.dbPrefix+id)
}

func (p DatabaseProvider) getConfigRaw(id string) (any, error) {
	conn := p.pool.Get()
	defer conn.Close()
	return conn.Do("CONFIG", "GET", id)
}
func (p DatabaseProvider) getKeyString(id string) (string, bool) {
	result, err := redigo.String(p.getKeyRaw(id))
	if result == "" {
		return "", false
	}
	helper.Check(err)
	return result, true
}

func (p DatabaseProvider) getKeyInt(id string) (int, bool) {
	result, err := p.getKeyRaw(id)
	if result == nil {
		return 0, false
	}
	resultInt, err2 := redigo.Int(result, err)
	helper.Check(err2)
	return resultInt, true
}

func (p DatabaseProvider) getKeyUInt64(id string) (uint64, bool) {
	result, err := p.getKeyRaw(id)
	if result == nil {
		return 0, false
	}
	resultInt, err2 := redigo.Uint64(result, err)
	helper.Check(err2)
	return resultInt, true
}

func (p DatabaseProvider) getKeyInt64(id string) (int64, bool) {
	result, err := p.getKeyRaw(id)
	if result == nil {
		return 0, false
	}
	resultInt, err2 := redigo.Int64(result, err)
	helper.Check(err2)
	return resultInt, true
}

func (p DatabaseProvider) getKeyBytes(id string) ([]byte, bool) {
	result, err := p.getKeyRaw(id)
	if result == nil {
		return nil, false
	}
	resultInt, err2 := redigo.Bytes(result, err)
	helper.Check(err2)
	return resultInt, true
}

func (p DatabaseProvider) getHashMap(id string) ([]any, bool) {
	conn := p.pool.Get()
	defer conn.Close()
	result, err := redigo.Values(conn.Do("HGETALL", p.dbPrefix+id))
	helper.Check(err)
	if len(result) == 0 {
		return nil, false
	}
	return result, true
}

func (p DatabaseProvider) buildArgs(id string) redigo.Args {
	return redigo.Args{}.Add(p.dbPrefix + id)
}

func (p DatabaseProvider) setHashMap(content redigo.Args) {
	conn := p.pool.Get()
	defer conn.Close()
	_, err := conn.Do("HMSET", content...)
	helper.Check(err)
}

func (p DatabaseProvider) setExpiryAt(id string, expiry int64) {
	conn := p.pool.Get()
	defer conn.Close()
	_, err := conn.Do("EXPIREAT", p.dbPrefix+id, strconv.FormatInt(expiry, 10))
	helper.Check(err)
}
func (p DatabaseProvider) setExpiryInSeconds(id string, expiry int64) {
	conn := p.pool.Get()
	defer conn.Close()
	_, err := conn.Do("EXPIRE", p.dbPrefix+id, strconv.FormatInt(expiry, 10))
	helper.Check(err)
}

func (p DatabaseProvider) deleteKey(id string) {
	conn := p.pool.Get()
	defer conn.Close()
	_, err := conn.Do("DEL", p.dbPrefix+id)
	helper.Check(err)
}

func (p DatabaseProvider) increaseHashmapIntField(id string, field string) {
	conn := p.pool.Get()
	defer conn.Close()
	_, err := conn.Do("HINCRBY", p.dbPrefix+id, field, 1)
	helper.Check(err)
}

// acquireWindowedDownload atomically lets one request through to a resource whose access is
// bounded by a download window: it serves free while a window opened after windowOpenSince is
// still open, and otherwise opens a new one, which decrements decrementField (only if it is
// greater than 0) and stamps windowField with timeNow. incrementField, when not empty, is bumped
// alongside the decrement - a file has a DownloadCount to pair with its DownloadsRemaining, a
// bundle does not.
//
// The whole sequence runs as a single Lua script, which Redis executes atomically - this is what
// keeps the operation safe even with multiple Gokapi instances sharing this Redis server, and it
// is also why there is no counterpart here to the SQL providers' third step: their three
// statements are individually atomic but not collectively, so a caller that loses the race to
// open a window has to re-check for the winner's. No caller can lose that race here, because no
// second caller can run at all while this script does.
//
// Returns 0 when the request is refused, 1 when it is served inside an open window, and 2 when it
// opened a new one.
func (p DatabaseProvider) acquireWindowedDownload(id, windowField, decrementField, incrementField string, timeNow, windowOpenSince int64) int {
	const script = `
local windowOpenedAt = tonumber(redis.call('HGET', KEYS[1], ARGV[1]))
if windowOpenedAt ~= nil and windowOpenedAt > tonumber(ARGV[4]) then
	return 1
end
local current = tonumber(redis.call('HGET', KEYS[1], ARGV[2]))
if current == nil or current <= 0 then
	return 0
end
redis.call('HINCRBY', KEYS[1], ARGV[2], -1)
if ARGV[3] ~= '' then
	redis.call('HINCRBY', KEYS[1], ARGV[3], 1)
end
redis.call('HSET', KEYS[1], ARGV[1], ARGV[5])
return 2
`
	conn := p.pool.Get()
	defer conn.Close()
	result, err := conn.Do("EVAL", script, "1", p.dbPrefix+id, windowField, decrementField, incrementField,
		windowOpenSince, timeNow)
	resultInt, err2 := redigo.Int(result, err)
	helper.Check(err2)
	return resultInt
}

// deleteHashmapField removes a single field from a hash, leaving the rest of
// the hash intact.
func (p DatabaseProvider) deleteHashmapField(id string, field string) {
	conn := p.pool.Get()
	defer conn.Close()
	_, err := conn.Do("HDEL", p.dbPrefix+id, field)
	helper.Check(err)
}

func (p DatabaseProvider) setHashmapField(id string, field string, content any) {
	conn := p.pool.Get()
	defer conn.Close()
	_, err := conn.Do("HSET", p.dbPrefix+id, field, content)
	helper.Check(err)
}

func (p DatabaseProvider) getIncreasedInt(id string) int {
	conn := p.pool.Get()
	defer conn.Close()
	result, err := conn.Do("INCR", p.dbPrefix+id)
	resultInt, err2 := redigo.Int(result, err)
	helper.Check(err2)
	return resultInt
}

func (p DatabaseProvider) runEval(cmd string) {
	conn := p.pool.Get()
	defer conn.Close()
	_, err := conn.Do("EVAL", cmd, "0")
	helper.Check(err)
}

func (p DatabaseProvider) deleteAllWithPrefix(prefix string) {
	p.runEval("for _,k in ipairs(redis.call('keys','" + p.dbPrefix + prefix + "*')) do redis.call('del',k) end")
}

var osExit = os.Exit

func (p DatabaseProvider) deleteHashField(id, field string) {
	conn := p.pool.Get()
	defer conn.Close()
	_, err := conn.Do("HDEL", p.dbPrefix+id, field)
	helper.Check(err)
}
