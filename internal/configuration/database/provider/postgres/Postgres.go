package postgres

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
	// Required for the postgres driver
	_ "github.com/jackc/pgx/v5/stdlib"
)

// retryAttempts is how often a statement is retried when it fails with a
// transient error. Unlike SQLite, this provider talks over a network to a
// managed server that drops idle connections, fails over and restarts, so a
// single failed call is not necessarily a fatal condition.
const retryAttempts = 3

// retryDelay is the pause between attempts
const retryDelay = 150 * time.Millisecond

// isTransient reports whether an error is worth retrying. It matches on the
// driver's connection-level failures rather than on SQL errors, so a genuine
// constraint violation still surfaces immediately.
func isTransient(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, sql.ErrNoRows) {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, s := range []string{
		"connection refused",
		"connection reset",
		"broken pipe",
		"bad connection",
		"server closed the connection",
		"the database system is starting up",
		"the database system is shutting down",
		"terminating connection due to administrator command",
		"connection timed out",
		"i/o timeout",
		"eof",
	} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// exec runs a statement, retrying transient network failures
func (p DatabaseProvider) exec(query string, args ...any) (sql.Result, error) {
	var result sql.Result
	var err error
	for attempt := 0; attempt < retryAttempts; attempt++ {
		result, err = p.postgresDb.Exec(query, args...)
		if !isTransient(err) {
			return result, err
		}
		time.Sleep(retryDelay)
	}
	return result, err
}

// query runs a query, retrying transient network failures
func (p DatabaseProvider) query(q string, args ...any) (*sql.Rows, error) {
	var rows *sql.Rows
	var err error
	for attempt := 0; attempt < retryAttempts; attempt++ {
		rows, err = p.postgresDb.Query(q, args...)
		if !isTransient(err) {
			return rows, err
		}
		time.Sleep(retryDelay)
	}
	return rows, err
}

// queryRow runs a single-row query. Errors surface on Scan, so a transient
// failure is detected by probing the row error before returning it.
func (p DatabaseProvider) queryRow(q string, args ...any) *sql.Row {
	var row *sql.Row
	for attempt := 0; attempt < retryAttempts; attempt++ {
		row = p.postgresDb.QueryRow(q, args...)
		if !isTransient(row.Err()) {
			return row
		}
		time.Sleep(retryDelay)
	}
	return row
}

// DatabaseProvider contains the database instance
type DatabaseProvider struct {
	postgresDb *sql.DB
}

// DatabaseSchemeVersion contains the version number to be expected from the current database. If lower, an upgrade will be performed
const DatabaseSchemeVersion = 28

// New returns an instance
func New(dbConfig models.DbConnection) (DatabaseProvider, error) {
	return DatabaseProvider{}.init(dbConfig)
}

// GetType returns 2, for being a Postgres interface
func (p DatabaseProvider) GetType() int {
	return 2 // dbabstraction.TypePostgres
}

// Upgrade migrates the DB to a new Gokapi version, if required.
// The Postgres provider was introduced at DatabaseSchemeVersion 15, so there is no pre-15
// ladder; every step below covers a change made since.
func (p DatabaseProvider) Upgrade(currentDbVersion int) {
	if currentDbVersion > DatabaseSchemeVersion {
		fmt.Printf("Error: Database scheme version is %d, but this Gokapi version only supports up to %d. Please update Gokapi.\n",
			currentDbVersion, DatabaseSchemeVersion)
		osExit(1)
		return
	}
	// < v2.3.0
	if currentDbVersion < 16 {
		_, err := p.exec(`ALTER TABLE FileMetaData ADD COLUMN IF NOT EXISTS BundleId TEXT NOT NULL DEFAULT '';
		CREATE TABLE IF NOT EXISTS FileBundles (
			id	TEXT NOT NULL UNIQUE,
			name	TEXT NOT NULL,
			userid	INTEGER NOT NULL,
			creationdate	BIGINT NOT NULL,
			PRIMARY KEY(id)
		);`)
		helper.Check(err)
	}
	// < v2.4.0 (hybrid auth support)
	if currentDbVersion < 17 {
		_, err := p.exec(`ALTER TABLE Users ADD COLUMN IF NOT EXISTS AuthProvider TEXT NOT NULL DEFAULT 'internal';
		ALTER TABLE Users ADD COLUMN IF NOT EXISTS OidcSubject TEXT NOT NULL DEFAULT '';`)
		helper.Check(err)
		// Defence in depth on top of the DEFAULT above: any row written through the Go layer
		// with an explicit column list (see SaveUser) bypasses the column DEFAULT entirely, so
		// backfill any row that reaches this migration with an empty AuthProvider explicitly.
		_, err = p.exec(`UPDATE Users SET AuthProvider = 'internal' WHERE AuthProvider = '' OR AuthProvider IS NULL;`)
		helper.Check(err)
	}
	// < v2.4.1
	// Persists which auth method created a session, so a renewal recreates the same kind of
	// session (see sessionmanager.useSession) instead of inferring it from the current global
	// auth method - which is wrong in hybrid mode. IF NOT EXISTS makes this idempotent already.
	if currentDbVersion < 18 {
		_, err := p.exec(`ALTER TABLE Sessions ADD COLUMN IF NOT EXISTS IsOauth BOOLEAN NOT NULL DEFAULT false;`)
		helper.Check(err)
		// Every session that already existed before this column was added defaults to IsOauth =
		// false regardless of how it was actually created, since the DEFAULT above has no way to
		// know. Without wiping sessions here, a pre-v18 OAuth session would silently renew as a
		// password session from now on - skipping the OAuth recheck interval that is supposed to
		// re-verify its group membership on every renewal.
		p.DeleteAllSessions()
	}
	// < v2.5.0
	// External share recipients: their own tables, deliberately not the Users
	// table. IF NOT EXISTS keeps this idempotent, which matters because
	// Upgrade re-runs every step below the stored version on every boot.
	if currentDbVersion < 19 {
		_, err := p.exec(`CREATE TABLE IF NOT EXISTS ShareRecipients (
			id			SERIAL PRIMARY KEY,
			email		TEXT NOT NULL UNIQUE,
			createdat	BIGINT NOT NULL,
			lastloginat	BIGINT NOT NULL DEFAULT 0,
			isblocked	BOOLEAN NOT NULL DEFAULT false
		);
		CREATE TABLE IF NOT EXISTS ShareGrants (
			resourcetype		INTEGER NOT NULL,
			resourceid			TEXT NOT NULL,
			recipientid			INTEGER NOT NULL,
			grantedat			BIGINT NOT NULL,
			grantedby			INTEGER NOT NULL,
			downloadsused		INTEGER NOT NULL DEFAULT 0,
			downloadsallowed	INTEGER NOT NULL DEFAULT 0,
			lastdownloadat		BIGINT NOT NULL DEFAULT 0,
			PRIMARY KEY(resourcetype, resourceid, recipientid)
		);
		CREATE INDEX IF NOT EXISTS idx_sharegrants_recipient ON ShareGrants (recipientid);
		CREATE TABLE IF NOT EXISTS ShareLoginTokens (
			tokenhash		TEXT PRIMARY KEY,
			recipientid		INTEGER NOT NULL,
			resourcetype	INTEGER NOT NULL,
			resourceid		TEXT NOT NULL,
			createdat		BIGINT NOT NULL,
			expiresat		BIGINT NOT NULL,
			firstusedat		BIGINT NOT NULL DEFAULT 0,
			isrevoked		BOOLEAN NOT NULL DEFAULT false,
			requestedip		TEXT NOT NULL DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS idx_sharelogintokens_recipient ON ShareLoginTokens (recipientid);`)
		helper.Check(err)
	}
	// < v2.6.0
	// Optional encrypted storage of an auto-generated share password (see
	// configuration.StoreShareKeys and encryption.EncryptString). IF NOT EXISTS keeps this
	// idempotent; existing rows simply have no value, which is indistinguishable from "no key
	// stored" - the same state they were already in.
	if currentDbVersion < 20 {
		_, err := p.exec(`ALTER TABLE FileMetaData ADD COLUMN IF NOT EXISTS EncryptedSharePassword BYTEA;
		ALTER TABLE FileBundles ADD COLUMN IF NOT EXISTS EncryptedSharePassword BYTEA;`)
		helper.Check(err)
	}
	// Lets a request be closed before it is full or expired
	if currentDbVersion < 21 {
		_, err := p.exec(`ALTER TABLE UploadRequests ADD COLUMN IF NOT EXISTS Closed BOOLEAN NOT NULL DEFAULT FALSE;`)
		helper.Check(err)
	}
	// Encrypted file names. The column is only added here; the plaintext Name column is read,
	// re-encrypted into it and dropped by MigratePlaintextFileNames, which cannot run from this
	// ladder because Upgrade executes at boot, before an Input-level instance has been unsealed
	// and therefore before a master key exists to encrypt with.
	if currentDbVersion < 22 {
		_, err := p.exec(`ALTER TABLE FileMetaData ADD COLUMN IF NOT EXISTS NameEncrypted BYTEA;`)
		helper.Check(err)
	}
	// Encrypted folder and file request names, and file request notes - the same class of leak
	// FileMetaData.Name was fixed for at v22, missed for these three columns at the time. The
	// columns are only added here; the plaintext columns are read, re-encrypted into them and
	// dropped by MigratePlaintextFileNames, which cannot run from this ladder for the same reason
	// as the v22 step above.
	if currentDbVersion < 23 {
		_, err := p.exec(`ALTER TABLE FileBundles ADD COLUMN IF NOT EXISTS NameEncrypted BYTEA;
		ALTER TABLE UploadRequests ADD COLUMN IF NOT EXISTS NameEncrypted BYTEA;
		ALTER TABLE UploadRequests ADD COLUMN IF NOT EXISTS NoteEncrypted BYTEA;`)
		helper.Check(err)
	}
	// Metadata retention: a file whose content is disposed of keeps its row as history instead of
	// being deleted outright. Every row that already exists is active by definition - it has
	// content, so DisposedAt defaulting to 0 is correct with no backfill needed. IF NOT EXISTS
	// keeps this idempotent, same as the steps above.
	if currentDbVersion < 24 {
		_, err := p.exec(`ALTER TABLE FileMetaData ADD COLUMN IF NOT EXISTS DisposedAt BIGINT NOT NULL DEFAULT 0;
		ALTER TABLE FileMetaData ADD COLUMN IF NOT EXISTS DisposalReason INTEGER NOT NULL DEFAULT 0;`)
		helper.Check(err)
	}
	// File request collaborators (models.FileRequest.Collaborators): a JSON array of user ids,
	// typed JSONB so the server validates what is written. '[]' rather than '' as the default so
	// every row is valid JSON. IF NOT EXISTS keeps this idempotent, same as the steps above.
	if currentDbVersion < 25 {
		_, err := p.exec(`ALTER TABLE UploadRequests ADD COLUMN IF NOT EXISTS Collaborators JSONB NOT NULL DEFAULT '[]'::jsonb;`)
		helper.Check(err)
	}
	// File request retention (models.FileRequest.ClosedAt): the timestamp Closed last became true,
	// so storage.CleanUp's retention sweep can measure "closed for longer than N" the same way it
	// already measures "disposed for longer than N" off FileMetaData.DisposedAt. DEFAULT 0 for the
	// same reason as that column: every row that already exists was closed, if at all, before this
	// field could record when, so 0 ("unknown") is correct with no backfill possible. IF NOT EXISTS
	// keeps this idempotent, same as the steps above.
	if currentDbVersion < 26 {
		_, err := p.exec(`ALTER TABLE UploadRequests ADD COLUMN IF NOT EXISTS ClosedAt BIGINT NOT NULL DEFAULT 0;`)
		helper.Check(err)
	}
	// The folder as the unit of sharing: PasswordHash, ExpireAt, UnlimitedTime, DownloadsRemaining
	// and UnlimitedDownloads move from being inferred off member files onto FileBundles itself.
	// IF NOT EXISTS keeps this idempotent, same as the steps above. The backfill needs no master
	// key - see models.DeriveBundleSettingsFromMembers for the merge rule used when members
	// disagree - so it runs directly here instead of waiting for an unseal.
	if currentDbVersion < 27 {
		_, err := p.exec(`ALTER TABLE FileBundles ADD COLUMN IF NOT EXISTS PasswordHash TEXT NOT NULL DEFAULT '';
		ALTER TABLE FileBundles ADD COLUMN IF NOT EXISTS ExpireAt BIGINT NOT NULL DEFAULT 0;
		ALTER TABLE FileBundles ADD COLUMN IF NOT EXISTS UnlimitedTime BOOLEAN NOT NULL DEFAULT false;
		ALTER TABLE FileBundles ADD COLUMN IF NOT EXISTS DownloadsRemaining BIGINT NOT NULL DEFAULT 0;
		ALTER TABLE FileBundles ADD COLUMN IF NOT EXISTS UnlimitedDownloads BOOLEAN NOT NULL DEFAULT false;`)
		helper.Check(err)
		p.backfillBundleSettingsFromMembers()
	}
	// The download window: the timestamp the most recent window opened on a file and on a folder,
	// so access can end at whichever comes first, the resource's own expiry or the close of its
	// window (see models.DownloadAccess). Every row that already exists gets 0, "never opened",
	// which is closed under any leeway - so an upgrade with GOKAPI_DOWNLOAD_LEEWAY unset behaves
	// exactly as before. IF NOT EXISTS keeps this idempotent, same as the steps above.
	if currentDbVersion < 28 {
		_, err := p.exec(`ALTER TABLE FileMetaData ADD COLUMN IF NOT EXISTS WindowOpenedAt BIGINT NOT NULL DEFAULT 0;
		ALTER TABLE FileBundles ADD COLUMN IF NOT EXISTS WindowOpenedAt BIGINT NOT NULL DEFAULT 0;`)
		helper.Check(err)
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

// GetDbVersion gets the version number of the database.
// Postgres has no PRAGMA user_version, so the value is kept in a dedicated table.
func (p DatabaseProvider) GetDbVersion() int {
	var version int
	row := p.queryRow("SELECT Version FROM SchemaVersion WHERE Id = 1")
	err := row.Scan(&version)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0
		}
		helper.Check(err)
		return 0
	}
	return version
}

// SetDbVersion sets the version number of the database
func (p DatabaseProvider) SetDbVersion(newVersion int) {
	_, err := p.exec(`INSERT INTO SchemaVersion (Id, Version) VALUES (1, $1)
					ON CONFLICT (Id) DO UPDATE SET Version = EXCLUDED.Version`, newVersion)
	helper.Check(err)
}

// GetSchemaVersion returns the version number, which the database should be at if fully upgraded
func (p DatabaseProvider) GetSchemaVersion() int {
	return DatabaseSchemeVersion
}

// init connects to the database and creates the table structure, if necessary
func (p DatabaseProvider) init(dbConfig models.DbConnection) (DatabaseProvider, error) {
	if dbConfig.HostUrl == "" {
		return DatabaseProvider{}, errors.New("empty database url was provided")
	}
	if p.postgresDb == nil {
		var err error
		p.postgresDb, err = sql.Open("pgx", dbConfig.HostUrl)
		if err != nil {
			return DatabaseProvider{}, err
		}
		p.postgresDb.SetMaxOpenConns(10)
		p.postgresDb.SetMaxIdleConns(5)
		// A managed Postgres will silently drop idle connections and fail over.
		// Recycling connections keeps the pool from handing out dead ones.
		p.postgresDb.SetConnMaxLifetime(5 * time.Minute)
		p.postgresDb.SetConnMaxIdleTime(1 * time.Minute)

		err = p.postgresDb.Ping()
		if err != nil {
			return DatabaseProvider{}, err
		}
		return p, p.createNewDatabase()
	}
	return p, nil
}

// Close the database connection
func (p DatabaseProvider) Close() {
	if p.postgresDb != nil {
		err := p.postgresDb.Close()
		if err != nil {
			fmt.Println(err)
		}
	}
	p.postgresDb = nil
}

// RunGarbageCollection runs the databases GC
func (p DatabaseProvider) RunGarbageCollection() {
	p.cleanExpiredSessions()
	p.cleanApiKeys()
}

// createNewDatabase creates the table structure if it does not exist yet.
//
// Column order is deliberately identical to the SQLite provider: several queries
// use SELECT * with positional Scan, so reordering columns here would silently
// map values onto the wrong struct fields.
func (p DatabaseProvider) createNewDatabase() error {
	sqlStmt := `CREATE TABLE IF NOT EXISTS ApiKeys (
			Id	TEXT NOT NULL UNIQUE,
			FriendlyName	TEXT NOT NULL,
			LastUsed	BIGINT NOT NULL,
			Permissions	INTEGER NOT NULL DEFAULT 0,
			Expiry	BIGINT,
			IsSystemKey	INTEGER,
			UserId INTEGER NOT NULL,
			PublicId TEXT NOT NULL UNIQUE,
			UploadRequestId	TEXT NOT NULL,
			PRIMARY KEY(Id)
		);
		CREATE TABLE IF NOT EXISTS E2EConfig (
			Id	BIGINT GENERATED BY DEFAULT AS IDENTITY,
			Config	BYTEA NOT NULL,
			UserId INTEGER NOT NULL UNIQUE,
			PRIMARY KEY(Id)
		);
		CREATE TABLE IF NOT EXISTS FileMetaData (
			Id	TEXT NOT NULL UNIQUE,
			NameEncrypted	BYTEA,
			Size	TEXT NOT NULL,
			SHA1	TEXT NOT NULL,
			ExpireAt	BIGINT NOT NULL,
			SizeBytes	BIGINT NOT NULL,
			DownloadsRemaining	BIGINT NOT NULL,
			DownloadCount	BIGINT NOT NULL,
			PasswordHash	TEXT NOT NULL,
			HotlinkId	TEXT NOT NULL,
			ContentType	TEXT NOT NULL,
			AwsBucket	TEXT NOT NULL,
			Encryption	BYTEA NOT NULL,
			UnlimitedDownloads	INTEGER NOT NULL,
			UnlimitedTime	INTEGER NOT NULL,
			UserId	INTEGER NOT NULL,
			UploadDate	BIGINT NOT NULL,
			PendingDeletion	BIGINT NOT NULL,
			UploadRequestId	TEXT NOT NULL,
			BundleId	TEXT NOT NULL,
			EncryptedSharePassword	BYTEA,
			DisposedAt	BIGINT NOT NULL DEFAULT 0,
			DisposalReason	INTEGER NOT NULL DEFAULT 0,
			WindowOpenedAt	BIGINT NOT NULL DEFAULT 0,
			PRIMARY KEY(Id)
		);
		CREATE TABLE IF NOT EXISTS Hotlinks (
			Id	TEXT NOT NULL UNIQUE,
			FileId	TEXT NOT NULL UNIQUE,
			PRIMARY KEY(Id)
		);
		CREATE TABLE IF NOT EXISTS Sessions (
			Id	TEXT NOT NULL UNIQUE,
			RenewAt	BIGINT NOT NULL,
			ValidUntil	BIGINT NOT NULL,
			UserId	INTEGER NOT NULL,
			IsOauth	BOOLEAN NOT NULL DEFAULT false,
			PRIMARY KEY(Id)
		);
		CREATE TABLE IF NOT EXISTS Users (
			Id	INTEGER GENERATED BY DEFAULT AS IDENTITY,
			Name	TEXT NOT NULL UNIQUE,
			Password	TEXT,
			Permissions	BIGINT NOT NULL,
			Userlevel	INTEGER NOT NULL,
			LastOnline	BIGINT NOT NULL DEFAULT 0,
			ResetPassword	INTEGER NOT NULL DEFAULT 0,
			AuthProvider	TEXT NOT NULL DEFAULT 'internal',
			OidcSubject	TEXT NOT NULL DEFAULT '',
			PRIMARY KEY(Id)
		);
		CREATE TABLE IF NOT EXISTS UploadRequests (
			Id	TEXT NOT NULL UNIQUE,
			NameEncrypted	BYTEA,
			UserId	INTEGER NOT NULL,
			Expiry	BIGINT NOT NULL,
			MaxFiles	INTEGER NOT NULL,
			MaxSize	INTEGER NOT NULL,
			Creation	BIGINT NOT NULL,
			ApiKey	TEXT NOT NULL UNIQUE,
			NoteEncrypted	BYTEA,
			Closed	BOOLEAN NOT NULL DEFAULT FALSE,
			Collaborators	JSONB NOT NULL DEFAULT '[]'::jsonb,
			ClosedAt	BIGINT NOT NULL DEFAULT 0,
			PRIMARY KEY(Id)
		);
		CREATE TABLE IF NOT EXISTS Statistics (
			Id	INTEGER GENERATED BY DEFAULT AS IDENTITY,
			Type	INTEGER NOT NULL UNIQUE,
			Value	BIGINT,
			PRIMARY KEY(Id)
		);
		CREATE TABLE IF NOT EXISTS SchemaVersion (
			Id	INTEGER NOT NULL,
			Version	INTEGER NOT NULL,
			PRIMARY KEY(Id)
		);
		CREATE TABLE IF NOT EXISTS ShareRecipients (
			id			SERIAL PRIMARY KEY,
			email		TEXT NOT NULL UNIQUE,
			createdat	BIGINT NOT NULL,
			lastloginat	BIGINT NOT NULL DEFAULT 0,
			isblocked	BOOLEAN NOT NULL DEFAULT false
		);
		CREATE TABLE IF NOT EXISTS ShareGrants (
			resourcetype		INTEGER NOT NULL,
			resourceid			TEXT NOT NULL,
			recipientid			INTEGER NOT NULL,
			grantedat			BIGINT NOT NULL,
			grantedby			INTEGER NOT NULL,
			downloadsused		INTEGER NOT NULL DEFAULT 0,
			downloadsallowed	INTEGER NOT NULL DEFAULT 0,
			lastdownloadat		BIGINT NOT NULL DEFAULT 0,
			PRIMARY KEY(resourcetype, resourceid, recipientid)
		);
		CREATE INDEX IF NOT EXISTS idx_sharegrants_recipient ON ShareGrants (recipientid);
		CREATE TABLE IF NOT EXISTS ShareLoginTokens (
			tokenhash		TEXT PRIMARY KEY,
			recipientid		INTEGER NOT NULL,
			resourcetype	INTEGER NOT NULL,
			resourceid		TEXT NOT NULL,
			createdat		BIGINT NOT NULL,
			expiresat		BIGINT NOT NULL,
			firstusedat		BIGINT NOT NULL DEFAULT 0,
			isrevoked		BOOLEAN NOT NULL DEFAULT false,
			requestedip		TEXT NOT NULL DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS idx_sharelogintokens_recipient ON ShareLoginTokens (recipientid);
				CREATE TABLE IF NOT EXISTS FileBundles (
			id	TEXT NOT NULL UNIQUE,
			NameEncrypted	BYTEA,
			userid	INTEGER NOT NULL,
			creationdate	BIGINT NOT NULL,
			EncryptedSharePassword	BYTEA,
			PasswordHash	TEXT NOT NULL DEFAULT '',
			ExpireAt	BIGINT NOT NULL DEFAULT 0,
			UnlimitedTime	BOOLEAN NOT NULL DEFAULT false,
			DownloadsRemaining	BIGINT NOT NULL DEFAULT 0,
			UnlimitedDownloads	BOOLEAN NOT NULL DEFAULT false,
			WindowOpenedAt	BIGINT NOT NULL DEFAULT 0,
			PRIMARY KEY(id)
		);`
	err := p.rawPostgres(sqlStmt)
	if err != nil {
		return err
	}
	if p.GetDbVersion() == 0 {
		p.SetDbVersion(DatabaseSchemeVersion)
	}
	return nil
}

// rawPostgres runs a raw SQL statement. Should only be used for creating or upgrading the schema
func (p DatabaseProvider) rawPostgres(statement string) error {
	if p.postgresDb == nil {
		panic("Postgres not initialised")
	}
	_, err := p.postgresDb.Exec(statement)
	return err
}

var osExit = os.Exit
