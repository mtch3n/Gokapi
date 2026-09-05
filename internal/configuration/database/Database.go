package database

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/forceu/gokapi/internal/configuration/database/dbabstraction"
	"github.com/forceu/gokapi/internal/configuration/database/dbcache"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
)

var db dbabstraction.Database

// Connect establishes a connection to the database and creates the table structure, if necessary
func Connect(config models.DbConnection) {
	var err error
	dbcache.Init()
	db, err = dbabstraction.GetNew(config)
	if err != nil {
		panic(err)
	}
}

// ParseUrl converts a database URL to a models.DbConnection struct
func ParseUrl(dbUrl string, mustExist bool) (models.DbConnection, error) {
	if dbUrl == "" {
		return models.DbConnection{}, errors.New("dbUrl is empty")
	}
	u, err := url.Parse(dbUrl)
	if err != nil {
		return models.DbConnection{}, fmt.Errorf("unsupported database URL - expected format is: type://username:password@server: %v", err)
	}
	result := models.DbConnection{}
	switch strings.ToLower(u.Scheme) {
	case "sqlite":
		result.Type = dbabstraction.TypeSqlite
		result.HostUrl = strings.TrimPrefix(dbUrl, "sqlite://")
		if mustExist {
			exist, errEx := helper.FileExists(result.HostUrl)
			if errEx != nil {
				return models.DbConnection{}, errEx
			}
			if !exist {
				return models.DbConnection{}, fmt.Errorf("file %s does not exist\n", result.HostUrl)
			}
		}
	case "redis":
		result.Type = dbabstraction.TypeRedis
		result.HostUrl = u.Host
	case "postgres", "postgresql":
		result.Type = dbabstraction.TypePostgres
		// pgx consumes the full DSN, including credentials and query parameters such as sslmode.
		// Because HostUrl therefore contains the password, never print it unredacted - use RedactUrl.
		result.HostUrl = dbUrl
	default:
		return models.DbConnection{}, fmt.Errorf("unsupported database type: %s\n", RedactUrl(dbUrl))
	}

	query := u.Query()

	result.Username = u.User.Username()
	result.Password, _ = u.User.Password()
	result.RedisUseSsl = query.Has("ssl")
	result.RedisPrefix = query.Get("prefix")

	return result, nil
}

// Migrate copies a database to a new location
func Migrate(configOld, configNew models.DbConnection) {
	dbOld, err := dbabstraction.GetNew(configOld)
	helper.Check(err)
	dbNew, err := dbabstraction.GetNew(configNew)
	helper.Check(err)

	apiKeys := dbOld.GetAllApiKeys()
	for _, apiKey := range apiKeys {
		dbNew.SaveApiKey(apiKey)
	}
	users := dbOld.GetAllUsers()
	for _, user := range users {
		// A source below schema v9/v17 (e.g. an old Redis instance) can yield users with an empty
		// AuthProvider, since GetNew below only calls New() and never runs the destination's
		// Upgrade(), so the v9/v17 AuthProvider backfill never runs on the copied rows. SaveUser's
		// explicit column list bypasses the SQL DEFAULT, so an empty AuthProvider would be written
		// as '' rather than 'internal', and since AuthProvider is now checked as an allow-list on
		// both the OAuth and header-auth login doors, an empty provider is accepted by neither -
		// locking out every migrated user, including the super admin, with no recovery path.
		// Normalize here so migration can never produce an unusable AuthProvider.
		if user.AuthProvider == "" {
			user.AuthProvider = models.AuthProviderInternal
		}
		dbNew.SaveUser(user, false)
		dbNew.SaveEnd2EndInfo(dbOld.GetEnd2EndInfo(user.Id), user.Id)
	}
	files := dbOld.GetAllMetadata()
	for _, file := range files {
		dbNew.SaveMetaData(file)
		if file.HotlinkId != "" {
			dbNew.SaveHotlink(file)
		}
	}
	requests := dbOld.GetAllFileRequests()
	for _, request := range requests {
		dbNew.SaveFileRequest(request)
	}
	// File bundles were not copied before this change, so a migrated database
	// lost every folder while keeping the member files. Copied here because
	// bundles are also one of the resource types a share grant can point at,
	// and a grant on a bundle that no longer exists is unreachable.
	for _, bundle := range dbOld.GetAllFileBundles() {
		dbNew.SaveFileBundle(bundle)
	}
	migrateShareAccess(dbOld, dbNew)
	dbOld.Close()
	dbNew.Close()
}

// migrateShareAccess copies external recipients, their grants and their live
// links.
//
// Omitting the grants would be a silent fail-open, not merely lost data:
// whether a resource is restricted is derived from having any grant at all
// (see IsShareRestricted), so a migrated database with no grant rows reports
// every previously identity-restricted file as unrestricted, and its share
// link becomes anonymously downloadable.
//
// The recipient IDs are remapped rather than reused. The destination assigns
// its own IDs (SERIAL in Postgres, AUTOINCREMENT in SQLite, INCR in Redis), so
// carrying the source IDs across would attach grants to whichever unrelated
// recipient happened to land on that number.
func migrateShareAccess(dbOld, dbNew dbabstraction.Database) {
	idMapping := make(map[int]int)
	for _, recipient := range dbOld.GetAllShareRecipients() {
		sourceId := recipient.Id
		recipient.Id = 0
		idMapping[sourceId] = dbNew.SaveShareRecipient(recipient)
	}

	// Grants are grouped per resource, because SetShareGrants replaces the
	// whole list for a resource rather than appending one at a time.
	type resourceKey struct {
		resourceType int
		resourceId   string
	}
	grouped := make(map[resourceKey][]models.ShareGrant)
	for sourceId := range idMapping {
		for _, grant := range dbOld.GetShareGrantsForRecipient(sourceId) {
			key := resourceKey{grant.ResourceType, grant.ResourceId}
			grouped[key] = append(grouped[key], grant)
		}
	}
	for key, grants := range grouped {
		recipientIds := make([]int, 0, len(grants))
		for _, grant := range grants {
			if newId, ok := idMapping[grant.RecipientId]; ok {
				recipientIds = append(recipientIds, newId)
			}
		}
		if len(recipientIds) == 0 {
			continue
		}
		dbNew.SetShareGrants(key.resourceType, key.resourceId, recipientIds,
			grants[0].GrantedBy, grants[0].DownloadsAllowed)
		// The destination has no grants yet, so every one of these is written
		// fresh with a counter of zero. The downloads each recipient has
		// already taken are replayed afterwards; without this a migration would
		// hand every recipient a fresh allowance.
		for _, grant := range grants {
			newId, ok := idMapping[grant.RecipientId]
			if !ok {
				continue
			}
			for i := 0; i < grant.DownloadsUsed; i++ {
				// leeway 0, so every one of these opens its own window and therefore actually
				// spends one - a migration must reproduce the count, not a single window.
				dbNew.AcquireShareGrantDownload(key.resourceType, key.resourceId, newId, time.Now().Unix(), 0)
			}
		}
	}

	// Links are carried over too. Dropping them would fail closed rather than
	// open, but every recipient's mailed link would stop working at once with
	// no bulk way to reissue them.
	for _, token := range dbOld.GetAllShareLoginTokens() {
		newId, ok := idMapping[token.RecipientId]
		if !ok {
			continue
		}
		token.RecipientId = newId
		dbNew.SaveShareLoginToken(token)
	}
}

// MigratePlaintextFileNames re-encrypts any file name that a version predating encrypted file
// names left in plaintext, and reports how many files were converted. Safe to call repeatedly:
// once there is nothing left to convert it does no work and returns 0.
//
// Called after unsealing rather than from Upgrade because encrypting needs the master key, which
// an instance running at an Input encryption level does not hold while it is still sealed.
func MigratePlaintextFileNames() int {
	return db.MigratePlaintextFileNames()
}

// RunGarbageCollection runs the databases GC
func RunGarbageCollection() {
	db.RunGarbageCollection()
}

var osExit = os.Exit

// Upgrade migrates the DB to a new Gokapi version, if required
func Upgrade() {
	dbVersion := db.GetDbVersion()
	expectedVersion := db.GetSchemaVersion()
	if dbVersion > expectedVersion {
		fmt.Println("Error: Database is from a newer Gokapi version. Unable to continue.")
		osExit(1)
		return
	}
	if dbVersion < expectedVersion {
		db.Upgrade(dbVersion)
		db.SetDbVersion(expectedVersion)
		fmt.Printf("Successfully upgraded database to version %d\n", expectedVersion)
	}
}

// Close the database connection
func Close() {
	db.Close()
}

// Api Key Section

// GetAllApiKeys returns a map with all API keys
func GetAllApiKeys() map[string]models.ApiKey {
	return db.GetAllApiKeys()
}

// GetApiKey returns a models.ApiKey if valid or false if the ID is not valid
func GetApiKey(id string) (models.ApiKey, bool) {
	return db.GetApiKey(id)
}

// GetApiKeyByPublicKey returns an API key by using the public key
func GetApiKeyByPublicKey(publicKey string) (string, bool) {
	return db.GetApiKeyByPublicKey(publicKey)
}

// SaveApiKey saves the API key to the database
func SaveApiKey(apikey models.ApiKey) {
	db.SaveApiKey(apikey)
}

// UpdateTimeApiKey writes the content of LastUsage to the database
func UpdateTimeApiKey(apikey models.ApiKey) {
	// To reduce database writes, the entry is only updated if the last timestamp is more than 30 seconds old
	if dbcache.RequireSaveApiKeyUsage(apikey.Id) {
		db.UpdateTimeApiKey(apikey)
	}
}

// DeleteApiKey deletes an API key with the given ID
func DeleteApiKey(id string) {
	db.DeleteApiKey(id)
}

// E2E Section

// SaveEnd2EndInfo stores the encrypted e2e info
func SaveEnd2EndInfo(info models.E2EInfoEncrypted, userId int) {
	info.AvailableFiles = nil
	db.SaveEnd2EndInfo(info, userId)
}

// GetEnd2EndInfo retrieves the encrypted e2e info
func GetEnd2EndInfo(userId int) models.E2EInfoEncrypted {
	return db.GetEnd2EndInfo(userId)
}

// DeleteEnd2EndInfo resets the encrypted e2e info
func DeleteEnd2EndInfo(userId int) {
	db.DeleteEnd2EndInfo(userId)
}

// Hotlink Section

// GetHotlink returns the id of the file associated or false if not found
func GetHotlink(id string) (string, bool) {
	return db.GetHotlink(id)
}

// GetAllHotlinks returns an array with all hotlink ids
func GetAllHotlinks() []string {
	return db.GetAllHotlinks()
}

// SaveHotlink stores the hotlink associated with the file in the database
func SaveHotlink(file models.File) {
	db.SaveHotlink(file)
}

// DeleteHotlink deletes a hotlink with the given hotlink ID
func DeleteHotlink(id string) {
	db.DeleteHotlink(id)
}

// Metadata Section

// GetAllMetadata returns a map of all available files
func GetAllMetadata() map[string]models.File {
	return db.GetAllMetadata()
}

// GetMetaDataById returns a models.File from the ID passed or false if the id is not valid
func GetMetaDataById(id string) (models.File, bool) {
	return db.GetMetaDataById(id)
}

// SaveMetaData stores the metadata of a file to the disk
func SaveMetaData(file models.File) {
	db.SaveMetaData(file)
}

// DeleteMetaData deletes information about a file. Also removes its share
// grants and login tokens, so a metadata row deleted through any path other
// than storage.purgeFile/deleteFileHard (which already do this themselves)
// still cannot leave an orphaned, still-reachable share behind. Idempotent
// with those callers: a second DeleteShareGrants on the same resource finds
// nothing left to remove.
func DeleteMetaData(id string) {
	db.DeleteMetaData(id)
	db.DeleteShareGrants(models.ShareResourceFile, id)
}

// AcquireDownload spends one download: DownloadsRemaining-1, DownloadCount+1,
// WindowOpenedAt=timeNow, only if DownloadsRemaining > 0. Returns whether it did. Never grants
// for free - see dbabstraction.Database.
func AcquireDownload(id string, timeNow int64) bool {
	return db.AcquireDownload(id, timeNow)
}

// IncreaseDownloadCount atomically increases the download count of a file, leaving its allowance
// and its window untouched. Only for a file with UnlimitedDownloads set.
func IncreaseDownloadCount(id string) {
	db.IncreaseDownloadCount(id)
}

// Session Section

// GetSession returns the session with the given ID or false if not a valid ID
func GetSession(id string) (models.Session, bool) {
	return db.GetSession(id)
}

// SaveSession stores the given session. After the expiry passed, it will be deleted automatically
func SaveSession(id string, session models.Session) {
	db.SaveSession(id, session)
}

// DeleteSession deletes a session with the given ID
func DeleteSession(id string) {
	db.DeleteSession(id)
}

// DeleteAllSessions logs all users out
func DeleteAllSessions() {
	db.DeleteAllSessions()
}

// DeleteAllSessionsByUser logs the specific users out
func DeleteAllSessionsByUser(userId int) {
	db.DeleteAllSessionsByUser(userId)
}

// User Section

// GetAllUsers returns a map with all users
func GetAllUsers() []models.User {
	return db.GetAllUsers()
}

// GetUser returns a models.User if valid or false if the ID is not valid
func GetUser(id int) (models.User, bool) {
	return db.GetUser(id)
}

// GetUserByName returns a models.User if valid or false if the email is not valid
func GetUserByName(username string) (models.User, bool) {
	username = strings.ToLower(username)
	return db.GetUserByName(username)
}

// SaveUser saves a user to the database. If isNewUser is true, a new Id will be generated
func SaveUser(user models.User, isNewUser bool) {
	if user.Name == "" {
		panic("username cannot be empty")
	}
	user.Name = strings.ToLower(user.Name)
	db.SaveUser(user, isNewUser)
}

// UpdateUserLastOnline writes the last online time to the database
func UpdateUserLastOnline(id int) {
	// To reduce database writes, the entry is only updated if the last timestamp is more than 30 seconds old
	if dbcache.RequireSaveUserOnline(id) {
		db.UpdateUserLastOnline(id)
	}
}

// DeleteUser deletes a user with the given ID
func DeleteUser(id int) {
	db.DeleteUser(id)
}

// GetShareRecipientByEmail returns the recipient with this email, or false.
func GetShareRecipientByEmail(email string) (models.ShareRecipient, bool) {
	return db.GetShareRecipientByEmail(NormaliseRecipientEmail(email))
}

// GetShareRecipient returns the recipient with this ID, or false.
func GetShareRecipient(id int) (models.ShareRecipient, bool) {
	return db.GetShareRecipient(id)
}

// SaveShareRecipient stores a recipient, returning the row's ID.
func SaveShareRecipient(recipient models.ShareRecipient) int {
	recipient.Email = NormaliseRecipientEmail(recipient.Email)
	return db.SaveShareRecipient(recipient)
}

// GetAllShareRecipients returns every recipient, ordered by email.
func GetAllShareRecipients() []models.ShareRecipient {
	return db.GetAllShareRecipients()
}

// DeleteShareRecipient removes a recipient and everything that points at them.
func DeleteShareRecipient(id int) {
	db.DeleteShareRecipient(id)
}

// NormaliseRecipientEmail lower-cases and trims an address, so that the same
// mailbox typed with different casing resolves to one recipient rather than
// several. Normalisation happens here, at the single boundary into the
// database, so no caller can bypass it.
func NormaliseRecipientEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// SetShareGrants replaces the recipient list for one resource.
// downloadsAllowed is the per-recipient budget; 0 means unlimited.
func SetShareGrants(resourceType int, resourceId string, recipientIds []int, grantedBy int, downloadsAllowed int) {
	db.SetShareGrants(resourceType, resourceId, recipientIds, grantedBy, downloadsAllowed)
}

// AcquireShareGrantDownload atomically records one download by this recipient, returning
// granted=false when their allowance is already spent - there is no free ride any more for a
// request that merely arrives inside the window a previous spend opened (D24); see the provider
// implementation for why.
func AcquireShareGrantDownload(resourceType int, resourceId string, recipientId int, timeNow, leeway int64) (bool, bool) {
	return db.AcquireShareGrantDownload(resourceType, resourceId, recipientId, timeNow, leeway)
}

// GetShareGrants returns every grant on a resource.
func GetShareGrants(resourceType int, resourceId string) []models.ShareGrant {
	return db.GetShareGrants(resourceType, resourceId)
}

// GetAllShareGrants returns every grant in the database, for the callers that resolve every
// file's access axes in one pass rather than one resource at a time.
func GetAllShareGrants() []models.ShareGrant {
	return db.GetAllShareGrants()
}

// HasShareGrant reports whether this recipient may reach this resource.
func HasShareGrant(resourceType int, resourceId string, recipientId int) bool {
	return db.HasShareGrant(resourceType, resourceId, recipientId)
}

// GetShareGrantsForRecipient returns every grant the recipient holds.
func GetShareGrantsForRecipient(recipientId int) []models.ShareGrant {
	return db.GetShareGrantsForRecipient(recipientId)
}

// DeleteShareGrants removes every grant on a resource.
func DeleteShareGrants(resourceType int, resourceId string) {
	db.DeleteShareGrants(resourceType, resourceId)
}

// IsShareRestricted reports whether the resource has a recipient list, and is
// therefore reachable only by a recipient holding a grant.
func IsShareRestricted(resourceType int, resourceId string) bool {
	return len(db.GetShareGrants(resourceType, resourceId)) > 0
}

// SaveShareLoginToken stores a magic link.
func SaveShareLoginToken(token models.ShareLoginToken) {
	db.SaveShareLoginToken(token)
}

// GetShareLoginToken returns the token with this hash, or false.
func GetShareLoginToken(tokenHash string) (models.ShareLoginToken, bool) {
	return db.GetShareLoginToken(tokenHash)
}

// MarkShareLoginTokenUsed records the first redemption, for audit only.
func MarkShareLoginTokenUsed(tokenHash string, usedAt int64) {
	db.MarkShareLoginTokenUsed(tokenHash, usedAt)
}

// GetLastShareLoginTokenTime returns when the most recent link for this
// recipient and resource was issued, or 0 if there is none.
func GetLastShareLoginTokenTime(recipientId int, resourceType int, resourceId string) int64 {
	return db.GetLastShareLoginTokenTime(recipientId, resourceType, resourceId)
}

// RevokeShareLoginTokens retires every live link for this recipient and
// resource.
func RevokeShareLoginTokens(recipientId int, resourceType int, resourceId string) {
	db.RevokeShareLoginTokens(recipientId, resourceType, resourceId)
}

// CleanUpExpiredShareLoginTokens removes links that have expired.
func CleanUpExpiredShareLoginTokens(now int64) {
	db.CleanUpExpiredShareLoginTokens(now)
}

// GetSuperAdmin returns the models.User data for the super admin
func GetSuperAdmin() (models.User, bool) {
	users := db.GetAllUsers()
	for _, user := range users {
		if user.IsSuperAdmin() {
			return user, true
		}
	}
	return models.User{}, false
}

// EditSuperAdmin changes parameters of the super admin. If no user exists, a new superadmin will be created
// Returns an error if at least one user exists, but no superadmin
func EditSuperAdmin(username, passwordHash string) error {
	user, ok := GetSuperAdmin()
	if !ok {
		if len(GetAllUsers()) != 0 {
			return errors.New("at least one user exists, but no superadmin found")
		}
		newAdmin := models.User{
			Name:         username,
			Permissions:  models.UserPermissionAll,
			UserLevel:    models.UserLevelSuperAdmin,
			Password:     passwordHash,
			AuthProvider: models.AuthProviderInternal,
		}
		db.SaveUser(newAdmin, true)
		return nil
	}
	if username != "" {
		user.Name = username
	}
	if passwordHash != "" {
		user.Password = passwordHash
	}
	db.SaveUser(user, false)
	return nil
}

// File Requests

// GetFileRequest returns the FileRequest or false if not found
func GetFileRequest(id string) (models.FileRequest, bool) {
	return db.GetFileRequest(id)
}

// GetAllFileRequests returns an array with all file requests, ordered by creation date
func GetAllFileRequests() []models.FileRequest {
	return db.GetAllFileRequests()
}

// SaveFileRequest stores the file request associated with the file in the database
func SaveFileRequest(request models.FileRequest) {
	db.SaveFileRequest(request)
}

// DeleteFileRequest deletes a file request with the given ID, and cascades to
// its share grants and login tokens so every caller (filerequest.Delete,
// cleanInvalidFileRequests, expiry in storage.CleanUp) inherits the cleanup
// without having to call DeleteShareGrants itself.
func DeleteFileRequest(request models.FileRequest) {
	db.DeleteFileRequest(request)
	db.DeleteShareGrants(models.ShareResourceFileRequest, request.Id)
}

// File Bundles

// GetFileBundle returns the FileBundle or false if not found
func GetFileBundle(id string) (models.FileBundle, bool) {
	return db.GetFileBundle(id)
}

// GetAllFileBundles returns an array with all file bundles, ordered by creation date
func GetAllFileBundles() []models.FileBundle {
	return db.GetAllFileBundles()
}

// SaveFileBundle stores the file bundle in the database
func SaveFileBundle(bundle models.FileBundle) {
	db.SaveFileBundle(bundle)
}

// DeleteFileBundle deletes a file bundle with the given ID, and cascades to
// its share grants and login tokens so every caller (filebundle.Delete,
// cleanInvalidBundles) inherits the cleanup without having to call
// DeleteShareGrants itself.
func DeleteFileBundle(bundle models.FileBundle) {
	db.DeleteFileBundle(bundle)
	db.DeleteShareGrants(models.ShareResourceBundle, bundle.Id)
}

// AcquireBundleDownload spends one visit to a bundle's content: DownloadsRemaining-1 and
// WindowOpenedAt=timeNow, only if DownloadsRemaining > 0. Returns whether it did. Never grants
// for free - see dbabstraction.Database.
func AcquireBundleDownload(id string, timeNow int64) bool {
	return db.AcquireBundleDownload(id, timeNow)
}

// Statistics

// GetStatTraffic returns the total traffic from statistics
func GetStatTraffic() uint64 {
	return db.GetStatTraffic()
}

// SaveStatTraffic stores the total traffic
func SaveStatTraffic(totalTraffic uint64) {
	db.SaveStatTraffic(totalTraffic)
}

// SaveTrafficSince stores the beginning of traffic counting
func SaveTrafficSince(since int64) {
	db.SaveTrafficSince(since)
}

// GetTrafficSince gets the beginning of traffic counting
func GetTrafficSince() (int64, bool) {
	return db.GetTrafficSince()
}

// RedactUrl removes any password from a database URL so it can be safely logged.
// A Postgres DbConnection.HostUrl is the full DSN and therefore contains credentials.
func RedactUrl(dbUrl string) string {
	parsed, err := url.Parse(dbUrl)
	if err != nil || parsed.User == nil {
		return dbUrl
	}
	if _, hasPassword := parsed.User.Password(); !hasPassword {
		return dbUrl
	}
	return parsed.Redacted()
}
