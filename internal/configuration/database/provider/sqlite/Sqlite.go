package sqlite

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/forceu/gokapi/internal/environment"

	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
	// Required for the sqlite driver
	_ "modernc.org/sqlite"
)

// DatabaseProvider contains the database instance
type DatabaseProvider struct {
	sqliteDb *sql.DB
}

// DatabaseSchemeVersion contains the version number to be expected from the current database. If lower, an upgrade will be performed
const DatabaseSchemeVersion = 22

// New returns an instance
func New(dbConfig models.DbConnection) (DatabaseProvider, error) {
	return DatabaseProvider{}.init(dbConfig)
}

// GetType returns 0, for being a Sqlite interface
func (p DatabaseProvider) GetType() int {
	return 0 // dbabstraction.Sqlite
}

// Upgrade migrates the DB to a new Gokapi version, if required
func (p DatabaseProvider) Upgrade(currentDbVersion int) {
	// < v2.0.0
	if currentDbVersion < 10 {
		fmt.Println("Error: Gokapi runs >=v2.0.0, but Database is <v2.0.0. Please update to v2.0.0 first.")
		osExit(1)
		return
	}
	// < v2.2.0-dev
	if currentDbVersion < 11 {
		err := p.rawSqlite("ALTER TABLE FileMetaData DROP COLUMN ExpireAtString;")
		helper.Check(err)
	}
	// < v2.2.0-rc1
	if currentDbVersion < 12 {

		err := p.rawSqlite(`ALTER TABLE FileMetaData ADD COLUMN "UploadRequestId" TEXT NOT NULL DEFAULT '';
		ALTER TABLE ApiKeys ADD COLUMN "UploadRequestId" TEXT NOT NULL DEFAULT '';
		CREATE TABLE "UploadRequests" (
			"id"	TEXT NOT NULL UNIQUE,
			"name"	TEXT NOT NULL,
			"userid"	INTEGER NOT NULL,
			"expiry"	INTEGER NOT NULL,
			"maxFiles"	INTEGER NOT NULL,
			"maxSize"	INTEGER NOT NULL,
			"creation"	INTEGER NOT NULL,
			"apiKey"	TEXT NOT NULL UNIQUE,
			"note"	TEXT NOT NULL,
			PRIMARY KEY("id")
		);`)
		helper.Check(err)
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
	// < v2.2.0-rc2
	if currentDbVersion < 13 {
		err := p.rawSqlite(`CREATE TABLE "Statistics" (
				"id"	INTEGER NOT NULL,
				"type"	INTEGER NOT NULL UNIQUE,
				"value"	INTEGER,
				PRIMARY KEY("id" AUTOINCREMENT)
			);`)
		helper.Check(err)
	}

	// < v2.2.3
	if currentDbVersion < 14 {
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
	if currentDbVersion < 15 {
		p.DeleteAllSessions()
	}
	// < v2.3.0
	if currentDbVersion < 16 {
		err := p.rawSqlite(`ALTER TABLE FileMetaData ADD COLUMN "BundleId" TEXT NOT NULL DEFAULT '';
		CREATE TABLE "FileBundles" (
			"id"	TEXT NOT NULL UNIQUE,
			"name"	TEXT NOT NULL,
			"userid"	INTEGER NOT NULL,
			"creationdate"	INTEGER NOT NULL,
			PRIMARY KEY("id")
		);`)
		helper.Check(err)
	}
	// < v2.4.0
	// Each ADD COLUMN is guarded individually rather than run as one bare, unconditional
	// statement: SQLite has no "ADD COLUMN IF NOT EXISTS", and Upgrade re-runs every step below
	// the stored version on every boot. Without the guard, a process that died between the two
	// ALTER TABLE statements (or between either of them and the version bump at the end of
	// Upgrade, which only happens once the whole ladder has run) would panic with "duplicate
	// column name" on the next boot, on every boot after that - the same bricked-database failure
	// mode as the earlier Postgres migration bug, just for SQLite instead. The guard makes the
	// step safe to resume from any point without a transaction.
	if currentDbVersion < 17 {
		if !p.columnExists("Users", "AuthProvider") {
			err := p.rawSqlite(`ALTER TABLE Users ADD COLUMN "AuthProvider" TEXT NOT NULL DEFAULT 'internal';`)
			helper.Check(err)
		}
		if !p.columnExists("Users", "OidcSubject") {
			err := p.rawSqlite(`ALTER TABLE Users ADD COLUMN "OidcSubject" TEXT NOT NULL DEFAULT '';`)
			helper.Check(err)
		}
		// Defence in depth on top of the DEFAULT above: any row written through the Go layer
		// with an explicit column list (see SaveUser) bypasses the column DEFAULT entirely, so a
		// row saved between the ADD COLUMN above and this line - or any row that reaches this
		// migration already carrying an empty AuthProvider for some other reason - is backfilled
		// explicitly rather than relying on the DEFAULT alone. Safe to re-run: matches nothing
		// once every row already has a non-empty AuthProvider.
		err := p.rawSqlite(`UPDATE Users SET AuthProvider = 'internal' WHERE AuthProvider = '' OR AuthProvider IS NULL;`)
		helper.Check(err)
	}
	// < v2.4.1
	// Persists which auth method created a session, so a renewal recreates the same kind of
	// session (see sessionmanager.useSession) instead of inferring it from the current global
	// auth method - which is wrong in hybrid mode. Same idempotency guard as the v17 step above.
	if currentDbVersion < 18 {
		if !p.columnExists("Sessions", "IsOauth") {
			err := p.rawSqlite(`ALTER TABLE Sessions ADD COLUMN "IsOauth" INTEGER NOT NULL DEFAULT 0;`)
			helper.Check(err)
		}
		// Every session that already existed before this column was added defaults to IsOauth =
		// false regardless of how it was actually created, since the DEFAULT above has no way to
		// know. Without wiping sessions here, a pre-v18 OAuth session would silently renew as a
		// password session from now on - skipping the OAuth recheck interval that is supposed to
		// re-verify its group membership on every renewal. The last DeleteAllSessions in this
		// ladder was at v15, so any session created between v15 and v18 would otherwise straddle
		// this schema change with no valid IsOauth value.
		p.DeleteAllSessions()
	}
	// < v2.5.0
	// External share recipients: their own tables, deliberately not the Users
	// table. Same idempotency guard style as the v17 and v18 steps, since
	// Upgrade re-runs every step below the stored version on every boot and
	// the version is only bumped once the whole ladder completes.
	if currentDbVersion < 19 {
		// Each CREATE is guarded on its own rather than behind one check on the
		// first table. go-sqlite3 runs a multi-statement exec sequentially and
		// without a transaction, so a process death partway through would leave
		// the single guard permanently satisfied while the remaining tables
		// were never created, and every grant operation would then panic on
		// every boot. That is the same bricked-database mode the v17 step above
		// documents.
		if !p.tableExists("ShareRecipients") {
			err := p.rawSqlite(`CREATE TABLE "ShareRecipients" (
				"id"			INTEGER NOT NULL,
				"email"			TEXT NOT NULL UNIQUE,
				"createdat"		INTEGER NOT NULL,
				"lastloginat"	INTEGER NOT NULL DEFAULT 0,
				"isblocked"		INTEGER NOT NULL DEFAULT 0,
				PRIMARY KEY("id" AUTOINCREMENT)
			);`)
			helper.Check(err)
		}
		if !p.tableExists("ShareGrants") {
			err := p.rawSqlite(`CREATE TABLE "ShareGrants" (
				"resourcetype"		INTEGER NOT NULL,
				"resourceid"		TEXT NOT NULL,
				"recipientid"		INTEGER NOT NULL,
				"grantedat"			INTEGER NOT NULL,
				"grantedby"			INTEGER NOT NULL,
				"downloadsused"		INTEGER NOT NULL DEFAULT 0,
				"downloadsallowed"	INTEGER NOT NULL DEFAULT 0,
				"lastdownloadat"	INTEGER NOT NULL DEFAULT 0,
				PRIMARY KEY("resourcetype","resourceid","recipientid")
			);
			CREATE INDEX "idx_sharegrants_recipient" ON "ShareGrants" ("recipientid");`)
			helper.Check(err)
		}
		if !p.tableExists("ShareLoginTokens") {
			err := p.rawSqlite(`CREATE TABLE "ShareLoginTokens" (
				"tokenhash"		TEXT NOT NULL UNIQUE,
				"recipientid"	INTEGER NOT NULL,
				"resourcetype"	INTEGER NOT NULL,
				"resourceid"	TEXT NOT NULL,
				"createdat"		INTEGER NOT NULL,
				"expiresat"		INTEGER NOT NULL,
				"firstusedat"	INTEGER NOT NULL DEFAULT 0,
				"isrevoked"		INTEGER NOT NULL DEFAULT 0,
				"requestedip"	TEXT NOT NULL DEFAULT '',
				PRIMARY KEY("tokenhash")
			);
			CREATE INDEX "idx_sharelogintokens_recipient" ON "ShareLoginTokens" ("recipientid");`)
			helper.Check(err)
		}
	}
	// < v2.6.0
	// Optional encrypted storage of an auto-generated share password (see
	// configuration.StoreShareKeys and encryption.EncryptString). Existing rows simply have no
	// value, which is indistinguishable from "no key stored" - the same state they were already
	// in. Same idempotency guard style as the v17 step above.
	if currentDbVersion < 20 {
		if !p.columnExists("FileMetaData", "EncryptedSharePassword") {
			err := p.rawSqlite(`ALTER TABLE FileMetaData ADD COLUMN "EncryptedSharePassword" BLOB;`)
			helper.Check(err)
		}
		if !p.columnExists("FileBundles", "EncryptedSharePassword") {
			err := p.rawSqlite(`ALTER TABLE FileBundles ADD COLUMN "EncryptedSharePassword" BLOB;`)
			helper.Check(err)
		}
	}
	// Encrypted file names. The column is only added here; the plaintext Name column is read,
	// re-encrypted into it and dropped by MigratePlaintextFileNames, which cannot run from this
	// ladder because Upgrade executes at boot, before an Input-level instance has been unsealed
	// and therefore before a master key exists to encrypt with.
	if currentDbVersion < 22 {
		if !p.columnExists("FileMetaData", "NameEncrypted") {
			err := p.rawSqlite(`ALTER TABLE FileMetaData ADD COLUMN "NameEncrypted" BLOB;`)
			helper.Check(err)
		}
	}
}

// tableExists returns true if the given table is present. Used to make a
// CREATE TABLE migration step idempotent.
func (p DatabaseProvider) tableExists(table string) bool {
	var name string
	row := p.sqliteDb.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name = ?", table)
	err := row.Scan(&name)
	if err != nil {
		return false
	}
	return name == table
}

// columnExists returns true if the given table has a column with the given name. Used to make
// an ALTER TABLE ADD COLUMN step idempotent, since SQLite has no ADD COLUMN IF NOT EXISTS.
func (p DatabaseProvider) columnExists(table, column string) bool {
	rows, err := p.sqliteDb.Query(fmt.Sprintf(`PRAGMA table_info("%s");`, table))
	helper.Check(err)
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull, pk int
		var dfltValue sql.NullString
		err = rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk)
		helper.Check(err)
		if strings.EqualFold(name, column) {
			return true
		}
	}
	helper.Check(rows.Err())
	return false
}

// GetDbVersion gets the version number of the database
func (p DatabaseProvider) GetDbVersion() int {
	var userVersion int
	row := p.sqliteDb.QueryRow("PRAGMA user_version;")
	err := row.Scan(&userVersion)
	helper.Check(err)
	return userVersion
}

// SetDbVersion sets the version number of the database
func (p DatabaseProvider) SetDbVersion(newVersion int) {
	_, err := p.sqliteDb.Exec(fmt.Sprintf("PRAGMA user_version = %d;", newVersion))
	helper.Check(err)
}

// GetSchemaVersion returns the version number, which the database should be at if fully upgraded
func (p DatabaseProvider) GetSchemaVersion() int {
	return DatabaseSchemeVersion
}

// Init connects to the database and creates the table structure, if necessary
func (p DatabaseProvider) init(dbConfig models.DbConnection) (DatabaseProvider, error) {
	if dbConfig.HostUrl == "" {
		return DatabaseProvider{}, errors.New("empty database url was provided")
	}
	if p.sqliteDb == nil {
		cleanPath := filepath.Clean(dbConfig.HostUrl)
		dataDir := filepath.Dir(cleanPath)
		var err error
		if !helper.FolderExists(dataDir) {
			err = os.MkdirAll(dataDir, 0700)
			if err != nil {
				return DatabaseProvider{}, err
			}
		}
		p.sqliteDb, err = sql.Open("sqlite", cleanPath+"?_pragma=busy_timeout=30000&_pragma=journal_mode=WAL")
		if err != nil {
			return DatabaseProvider{}, err
		}
		p.sqliteDb.SetMaxOpenConns(5)
		p.sqliteDb.SetMaxIdleConns(5)

		exists, err := helper.FileExists(dbConfig.HostUrl)
		helper.Check(err)
		if !exists {
			return p, p.createNewDatabase()
		}
		err = p.sqliteDb.Ping()
		return p, err
	}
	return p, nil
}

// Close the database connection
func (p DatabaseProvider) Close() {
	if p.sqliteDb != nil {
		err := p.sqliteDb.Close()
		if err != nil {
			fmt.Println(err)
		}
	}
	p.sqliteDb = nil
}

// RunGarbageCollection runs the databases GC
func (p DatabaseProvider) RunGarbageCollection() {
	p.cleanExpiredSessions()
	p.cleanApiKeys()
}

func (p DatabaseProvider) createNewDatabase() error {
	sqlStmt := `CREATE TABLE "ApiKeys" (
			"Id"	TEXT NOT NULL UNIQUE,
			"FriendlyName"	TEXT NOT NULL,
			"LastUsed"	INTEGER NOT NULL,
			"Permissions"	INTEGER NOT NULL DEFAULT 0,
			"Expiry"	INTEGER,
			"IsSystemKey"	INTEGER,
			"UserId" INTEGER NOT NULL,
			"PublicId" TEXT NOT NULL UNIQUE ,
			"UploadRequestId"	TEXT NOT NULL,
			PRIMARY KEY("Id")
		) WITHOUT ROWID;
		CREATE TABLE "E2EConfig" (
			"id"	INTEGER NOT NULL UNIQUE,
			"Config"	BLOB NOT NULL,
			"UserId" INTEGER NOT NULL UNIQUE,
			PRIMARY KEY("id" AUTOINCREMENT)
		);
		CREATE TABLE "FileMetaData" (
			"Id"	TEXT NOT NULL UNIQUE,
			"NameEncrypted"	BLOB,
			"Size"	TEXT NOT NULL,
			"SHA1"	TEXT NOT NULL,
			"ExpireAt"	INTEGER NOT NULL,
			"SizeBytes"	INTEGER NOT NULL,
			"DownloadsRemaining"	INTEGER NOT NULL,
			"DownloadCount"	INTEGER NOT NULL,
			"PasswordHash"	TEXT NOT NULL,
			"HotlinkId"	TEXT NOT NULL,
			"ContentType"	TEXT NOT NULL,
			"AwsBucket"	TEXT NOT NULL,
			"Encryption"	BLOB NOT NULL,
			"UnlimitedDownloads"	INTEGER NOT NULL,
			"UnlimitedTime"	INTEGER NOT NULL,
			"UserId"	INTEGER NOT NULL,
			"UploadDate"	INTEGER NOT NULL,
			"PendingDeletion"	INTEGER NOT NULL,
			"UploadRequestId"	TEXT NOT NULL,
			"BundleId"	TEXT NOT NULL,
			"EncryptedSharePassword"	BLOB,
			PRIMARY KEY("Id")
		);
		CREATE TABLE "Hotlinks" (
			"Id"	TEXT NOT NULL UNIQUE,
			"FileId"	TEXT NOT NULL UNIQUE,
			PRIMARY KEY("Id")
		) WITHOUT ROWID;
		CREATE TABLE "Sessions" (
			"Id"	TEXT NOT NULL UNIQUE,
			"RenewAt"	INTEGER NOT NULL,
			"ValidUntil"	INTEGER NOT NULL,
			"UserId"	INTEGER NOT NULL,
			"IsOauth"	INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY("Id")
		) WITHOUT ROWID;
		CREATE TABLE "Users" (
			"Id"	INTEGER NOT NULL UNIQUE,
			"Name"	TEXT NOT NULL UNIQUE,
			"Password"	TEXT,
			"Permissions"	INTEGER NOT NULL,
			"Userlevel"	INTEGER NOT NULL,
			"LastOnline"	INTEGER NOT NULL DEFAULT 0,
			"ResetPassword"	INTEGER NOT NULL DEFAULT 0,
			"AuthProvider"	TEXT NOT NULL DEFAULT 'internal',
			"OidcSubject"	TEXT NOT NULL DEFAULT '',
			PRIMARY KEY("Id" AUTOINCREMENT)
		);
		CREATE TABLE "UploadRequests" (
			"id"	TEXT NOT NULL UNIQUE,
			"name"	TEXT,
			"userid"	INTEGER NOT NULL,
			"expiry"	INTEGER NOT NULL,
			"maxFiles"	INTEGER NOT NULL,
			"maxSize"	INTEGER NOT NULL,
			"creation"	INTEGER NOT NULL,
			"apiKey"	TEXT NOT NULL UNIQUE,
			"note"	TEXT NOT NULL,
			PRIMARY KEY("id")
		);
		CREATE TABLE "Statistics" (
				"id"	INTEGER NOT NULL,
				"type"	INTEGER NOT NULL UNIQUE,
				"value"	INTEGER,
				PRIMARY KEY("id" AUTOINCREMENT)
			);
		CREATE TABLE "ShareRecipients" (
			"id"			INTEGER NOT NULL,
			"email"			TEXT NOT NULL UNIQUE,
			"createdat"		INTEGER NOT NULL,
			"lastloginat"	INTEGER NOT NULL DEFAULT 0,
			"isblocked"		INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY("id" AUTOINCREMENT)
		);
		CREATE TABLE "ShareGrants" (
			"resourcetype"	INTEGER NOT NULL,
			"resourceid"	TEXT NOT NULL,
			"recipientid"	INTEGER NOT NULL,
			"grantedat"		INTEGER NOT NULL,
			"grantedby"		INTEGER NOT NULL,
			"downloadsused"		INTEGER NOT NULL DEFAULT 0,
			"downloadsallowed"	INTEGER NOT NULL DEFAULT 0,
			"lastdownloadat"	INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY("resourcetype","resourceid","recipientid")
		);
		CREATE INDEX "idx_sharegrants_recipient" ON "ShareGrants" ("recipientid");
		CREATE TABLE "ShareLoginTokens" (
			"tokenhash"		TEXT NOT NULL UNIQUE,
			"recipientid"	INTEGER NOT NULL,
			"resourcetype"	INTEGER NOT NULL,
			"resourceid"	TEXT NOT NULL,
			"createdat"		INTEGER NOT NULL,
			"expiresat"		INTEGER NOT NULL,
			"firstusedat"	INTEGER NOT NULL DEFAULT 0,
			"isrevoked"		INTEGER NOT NULL DEFAULT 0,
			"requestedip"	TEXT NOT NULL DEFAULT '',
			PRIMARY KEY("tokenhash")
		);
		CREATE INDEX "idx_sharelogintokens_recipient" ON "ShareLoginTokens" ("recipientid");
				CREATE TABLE "FileBundles" (
			"id"	TEXT NOT NULL UNIQUE,
			"name"	TEXT NOT NULL,
			"userid"	INTEGER NOT NULL,
			"creationdate"	INTEGER NOT NULL,
			"EncryptedSharePassword"	BLOB,
			PRIMARY KEY("id")
		);`
	err := p.rawSqlite(sqlStmt)
	if err != nil {
		return err
	}
	p.SetDbVersion(DatabaseSchemeVersion)
	return nil
}

// rawSqlite runs a raw SQL statement. Should only be used for upgrading
func (p DatabaseProvider) rawSqlite(statement string) error {
	if p.sqliteDb == nil {
		panic("Sqlite not initialised")
	}
	_, err := p.sqliteDb.Exec(statement)
	return err
}

var osExit = os.Exit
