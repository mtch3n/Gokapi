package dbabstraction

import (
	"fmt"

	"github.com/forceu/gokapi/internal/configuration/database/provider/postgres"
	"github.com/forceu/gokapi/internal/configuration/database/provider/redis"
	"github.com/forceu/gokapi/internal/configuration/database/provider/sqlite"
	"github.com/forceu/gokapi/internal/models"
)

const (
	// TypeSqlite specifies to use an SQLite database
	TypeSqlite = iota
	// TypeRedis specifies to use a Redis database
	TypeRedis
	// TypePostgres specifies to use a PostgreSQL database
	TypePostgres
)

// Database declares the required functions for a database connection
type Database interface {
	// GetType returns identifier of the underlying interface
	GetType() int

	// Upgrade migrates the DB to a new Gokapi version, if required
	Upgrade(currentDbVersion int)
	// RunGarbageCollection runs the databases GC
	RunGarbageCollection()
	// Close the database connection
	Close()

	// GetDbVersion gets the version number of the database
	GetDbVersion() int
	// SetDbVersion sets the version number of the database
	SetDbVersion(newVersion int)
	// GetSchemaVersion returns the version number, that the database should be if fully upgraded
	GetSchemaVersion() int

	// GetAllApiKeys returns a map with all API keys
	GetAllApiKeys() map[string]models.ApiKey
	// GetApiKey returns a models.ApiKey if valid or false if the ID is not valid
	GetApiKey(id string) (models.ApiKey, bool)
	// SaveApiKey saves the API key to the database
	SaveApiKey(apikey models.ApiKey)
	// UpdateTimeApiKey writes the content of LastUsage to the database
	UpdateTimeApiKey(apikey models.ApiKey)
	// DeleteApiKey deletes an API key with the given ID
	DeleteApiKey(id string)
	// GetApiKeyByPublicKey returns an API key by using the public key
	GetApiKeyByPublicKey(publicKey string) (string, bool)

	// SaveEnd2EndInfo stores the encrypted e2e info
	SaveEnd2EndInfo(info models.E2EInfoEncrypted, userId int)
	// GetEnd2EndInfo retrieves the encrypted e2e info
	GetEnd2EndInfo(userId int) models.E2EInfoEncrypted
	// DeleteEnd2EndInfo resets the encrypted e2e info
	DeleteEnd2EndInfo(userId int)

	// GetHotlink returns the id of the file associated or false if not found
	GetHotlink(id string) (string, bool)
	// GetAllHotlinks returns an array with all hotlink ids
	GetAllHotlinks() []string
	// SaveHotlink stores the hotlink associated with the file in the database
	SaveHotlink(file models.File)
	// DeleteHotlink deletes a hotlink with the given hotlink ID
	DeleteHotlink(id string)

	// GetAllMetadata returns a map of all available files
	GetAllMetadata() map[string]models.File
	// GetMetaDataById returns a models.File from the ID passed or false if the id is not valid
	GetMetaDataById(id string) (models.File, bool)
	// SaveMetaData stores the metadata of a file to the disk
	SaveMetaData(file models.File)
	// MigratePlaintextFileNames re-encrypts any file name still stored in plaintext by a version
	// that predates encrypted names, removes the plaintext storage and returns how many files were
	// converted. Needs the master key, so it runs after unsealing rather than from Upgrade
	MigratePlaintextFileNames() int
	// DeleteMetaData deletes information about a file
	DeleteMetaData(id string)
	// AcquireDownload atomically lets one request through to a capped file's content. A request
	// that finds no download window open opens one, which spends one of DownloadsRemaining,
	// increments DownloadCount and records WindowOpenedAt; opened reports that. A request that
	// arrives while a window is open is granted without spending anything, so a broken or
	// resumed transfer does not cost the recipient their download. granted is false, and nothing
	// is written, once the allowance is exhausted and no window is open - the caller must not
	// serve the file then. leeway is how long a window stays open, in seconds; 0 makes every
	// request open its own window, which is the behaviour before windows existed. Never called
	// for a file with UnlimitedDownloads set - that is checked by the caller, not here.
	AcquireDownload(id string, timeNow, leeway int64) (granted, opened bool)
	// IncreaseDownloadCount atomically increases the download count of a file, leaving its
	// allowance and its window untouched. Only for a file with UnlimitedDownloads set, which has
	// no allowance to spend and no lifetime a window could bound.
	IncreaseDownloadCount(id string)

	// GetSession returns the session with the given ID or false if not a valid ID
	GetSession(id string) (models.Session, bool)
	// SaveSession stores the given session. After the expiry passed, it will be deleted automatically
	SaveSession(id string, session models.Session)
	// DeleteSession deletes a session with the given ID
	DeleteSession(id string)
	// DeleteAllSessions logs all users out
	DeleteAllSessions()
	// DeleteAllSessionsByUser logs the specific users out
	DeleteAllSessionsByUser(userId int)

	// GetAllUsers returns a map with all users
	GetAllUsers() []models.User
	// GetUser returns a models.User if valid or false if the ID is not valid
	GetUser(id int) (models.User, bool)
	// GetUserByName returns a models.User if valid or false if the username is not valid
	GetUserByName(email string) (models.User, bool)
	// SaveUser saves a user to the database. If isNewUser is true, a new Id will be generated
	SaveUser(user models.User, isNewUser bool)
	// UpdateUserLastOnline writes the last online time to the database
	UpdateUserLastOnline(id int)
	// DeleteUser deletes a user with the given ID
	DeleteUser(id int)

	// GetShareRecipientByEmail returns the recipient with this email, or false
	// if no such recipient exists. The email must already be normalised.
	GetShareRecipientByEmail(email string) (models.ShareRecipient, bool)
	// GetShareRecipient returns the recipient with this ID, or false.
	GetShareRecipient(id int) (models.ShareRecipient, bool)
	// SaveShareRecipient stores a recipient. An Id of 0 creates a new row and
	// returns the assigned ID; a non-zero Id updates in place.
	SaveShareRecipient(recipient models.ShareRecipient) int
	// GetAllShareRecipients returns every recipient, ordered by email.
	GetAllShareRecipients() []models.ShareRecipient
	// DeleteShareRecipient removes a recipient along with every grant, login
	// token and session they hold.
	DeleteShareRecipient(id int)

	// SetShareGrants replaces the recipient list for one resource. An empty
	// list clears it, returning the resource to an anonymous access mode.
	// Replacing rather than appending is what makes removing an address
	// actually revoke it instead of leaving a stale grant behind.
	// downloadsAllowed is the per-recipient budget; 0 means unlimited.
	SetShareGrants(resourceType int, resourceId string, recipientIds []int, grantedBy int, downloadsAllowed int)
	// GetShareGrants returns every grant on a resource.
	GetShareGrants(resourceType int, resourceId string) []models.ShareGrant
	// HasShareGrant reports whether this recipient may reach this resource.
	HasShareGrant(resourceType int, resourceId string, recipientId int) bool
	// GetShareGrantsForRecipient returns every grant the recipient holds.
	GetShareGrantsForRecipient(recipientId int) []models.ShareGrant
	// DeleteShareGrants removes every grant on a resource, and every login
	// token issued against it. Called whenever the resource is removed, or its
	// recipient list is cleared, so neither a grant nor a token can outlive
	// what it refers to.
	DeleteShareGrants(resourceType int, resourceId string)

	// AcquireShareGrantDownload atomically records one download by this recipient, under the
	// same window rule as AcquireDownload: the recipient's own allowance is spent only when this
	// call opens a window, and a request inside an open window is granted for free. granted is
	// false when the allowance is exhausted and no window is open, in which case the caller must
	// not serve the resource. The grant's lastdownloadat is the window start.
	AcquireShareGrantDownload(resourceType int, resourceId string, recipientId int, timeNow, leeway int64) (granted, opened bool)

	// SaveShareLoginToken stores a magic link.
	SaveShareLoginToken(token models.ShareLoginToken)
	// GetShareLoginToken returns the token with this hash, or false.
	GetShareLoginToken(tokenHash string) (models.ShareLoginToken, bool)
	// MarkShareLoginTokenUsed records the first redemption, for audit. The
	// link stays valid afterwards: it is reusable by design.
	MarkShareLoginTokenUsed(tokenHash string, usedAt int64)
	// GetLastShareLoginTokenTime returns the CreatedAt of the most recent link
	// issued for this recipient and resource, or 0 if there is none. Drives
	// the resend cooldown.
	GetLastShareLoginTokenTime(recipientId int, resourceType int, resourceId string) int64
	// RevokeShareLoginTokens retires every live link for this recipient and
	// resource. Called when a replacement is issued, so an old mail stops
	// working, and when access is withdrawn.
	RevokeShareLoginTokens(recipientId int, resourceType int, resourceId string)
	// GetAllShareLoginTokens returns every stored link. Used by Migrate, so a
	// database move carries the recipients' live links with it.
	GetAllShareLoginTokens() []models.ShareLoginToken
	// CleanUpExpiredShareLoginTokens removes links that have expired.
	CleanUpExpiredShareLoginTokens(now int64)

	// GetFileRequest returns the FileRequest or false if not found
	GetFileRequest(id string) (models.FileRequest, bool)
	// GetAllFileRequests returns an array with all file requests, ordered by creation date
	GetAllFileRequests() []models.FileRequest
	// SaveFileRequest stores the file request associated with the file in the database
	SaveFileRequest(request models.FileRequest)
	// DeleteFileRequest deletes a file request with the given ID
	DeleteFileRequest(request models.FileRequest)

	// GetFileBundle returns the FileBundle or false if not found
	GetFileBundle(id string) (models.FileBundle, bool)
	// GetAllFileBundles returns an array with all file bundles, ordered by creation date
	GetAllFileBundles() []models.FileBundle
	// SaveFileBundle stores the file bundle in the database
	SaveFileBundle(bundle models.FileBundle)
	// DeleteFileBundle deletes a file bundle with the given ID
	DeleteFileBundle(bundle models.FileBundle)
	// AcquireBundleDownload atomically lets one visit through to a bundle's content, under the
	// same window rule as AcquireDownload - the bundle owning the window rather than any member,
	// so a zip and a single member fetched inside the same window are one visit between them.
	// Never called for a bundle with UnlimitedDownloads set - that is checked by the caller, not
	// here.
	AcquireBundleDownload(id string, timeNow, leeway int64) (granted, opened bool)

	// GetStatTraffic returns the total traffic from statistics
	GetStatTraffic() uint64
	// SaveStatTraffic stores the total traffic
	SaveStatTraffic(totalTraffic uint64)
	// SaveTrafficSince stores the beginning of traffic counting
	SaveTrafficSince(since int64)
	// GetTrafficSince gets the beginning of traffic counting
	GetTrafficSince() (int64, bool)
}

// GetNew connects to the given database and initialises it
func GetNew(config models.DbConnection) (Database, error) {
	switch config.Type {
	case TypeSqlite:
		return sqlite.New(config)
	case TypeRedis:
		return redis.New(config)
	case TypePostgres:
		return postgres.New(config)
	default:
		return nil, fmt.Errorf("unsupported database: type %v", config.Type)
	}
}
