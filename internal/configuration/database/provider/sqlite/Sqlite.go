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
const DatabaseSchemeVersion = 29

// New returns an instance
func New(dbConfig models.DbConnection) (DatabaseProvider, error) {
	return DatabaseProvider{}.init(dbConfig)
}

// GetType returns 0, for being a Sqlite interface
func (p DatabaseProvider) GetType() int {
	return 0 // dbabstraction.Sqlite
}

// Upgrade migrates the DB to a new Gokapi version, if required.
//
// Every step below may only touch the schema as its OWN version defines it. That rules out
// calling this provider's model-facing methods - GetAllMetadata, GetAllUsers, SaveMetaData,
// SaveFileBundle and the rest - from a step, because those are written against the CURRENT schema
// and name every column it has, including columns a LATER step in this same ladder has not added
// yet. Such a call works right up until the next column is added and then fails at the worst
// possible moment: on a database several versions behind, part way through the ladder, with the
// earlier steps' DDL already committed and the older binary therefore no longer able to read it
// either. Every step below consequently issues its own statements, naming only columns that exist
// at its version; the steps that need to read data have a helper further down carrying their
// version in its name. DeleteAllSessions is the single exception, as it names no column at all.
//
// TestUpgradeFromEverySchemaVersion is what keeps this true: it builds a database at every
// version this ladder still accepts and runs the whole ladder against it.
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
		p.grantGuestUploadPermissionV12(environment.New().PermRequestGrantedByDefault)
		p.deleteSystemApiKeysV12()
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
		p.deleteSvgHotlinksV14()
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
	// Lets a request be closed before it is full or expired. GetFileRequest reads the table with
	// SELECT *, so the column has to be appended last here and in createNewDatabase alike, or the
	// two orders diverge and every Scan on an upgraded database reads the wrong column. Same
	// idempotency guard as the v17 step above.
	if currentDbVersion < 21 {
		if !p.columnExists("UploadRequests", "closed") {
			err := p.rawSqlite(`ALTER TABLE UploadRequests ADD COLUMN "closed" INTEGER NOT NULL DEFAULT 0;`)
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
	// Encrypted folder and file request names, and file request notes - the same class of leak
	// FileMetaData.Name was fixed for at v22, missed for these three columns at the time. Same
	// reasoning as the v22 step: the columns are only added here, the plaintext columns are read,
	// re-encrypted into them and dropped by MigratePlaintextFileNames, which cannot run from this
	// ladder because Upgrade executes at boot, before an Input-level instance has been unsealed.
	if currentDbVersion < 23 {
		if !p.columnExists("FileBundles", "NameEncrypted") {
			err := p.rawSqlite(`ALTER TABLE FileBundles ADD COLUMN "NameEncrypted" BLOB;`)
			helper.Check(err)
		}
		if !p.columnExists("UploadRequests", "NameEncrypted") {
			err := p.rawSqlite(`ALTER TABLE UploadRequests ADD COLUMN "NameEncrypted" BLOB;`)
			helper.Check(err)
		}
		if !p.columnExists("UploadRequests", "NoteEncrypted") {
			err := p.rawSqlite(`ALTER TABLE UploadRequests ADD COLUMN "NoteEncrypted" BLOB;`)
			helper.Check(err)
		}
	}
	// Metadata retention: a file whose content is disposed of keeps its row as history instead of
	// being deleted outright. Every row that already exists is active by definition - it has
	// content, so DisposedAt defaulting to 0 is correct with no backfill needed. Same idempotency
	// guard as the v17 step above.
	if currentDbVersion < 24 {
		if !p.columnExists("FileMetaData", "DisposedAt") {
			err := p.rawSqlite(`ALTER TABLE FileMetaData ADD COLUMN "DisposedAt" INTEGER NOT NULL DEFAULT 0;`)
			helper.Check(err)
		}
		if !p.columnExists("FileMetaData", "DisposalReason") {
			err := p.rawSqlite(`ALTER TABLE FileMetaData ADD COLUMN "DisposalReason" INTEGER NOT NULL DEFAULT 0;`)
			helper.Check(err)
		}
	}
	// File request collaborators (models.FileRequest.Collaborators): a JSON array of user ids.
	// '[]' rather than '' as the default so every row is valid JSON and the decoder has no
	// special case. Appended last, same reasoning as the v21 step above. Same idempotency guard
	// as the v17 step above.
	if currentDbVersion < 25 {
		if !p.columnExists("UploadRequests", "Collaborators") {
			err := p.rawSqlite(`ALTER TABLE UploadRequests ADD COLUMN "Collaborators" TEXT NOT NULL DEFAULT '[]';`)
			helper.Check(err)
		}
	}
	// File request retention (models.FileRequest.ClosedAt): the timestamp Closed last became true,
	// so storage.CleanUp's retention sweep can measure "closed for longer than N" the same way it
	// already measures "disposed for longer than N" off FileMetaData.DisposedAt. DEFAULT 0 for the
	// same reason as that column: every row that already exists was closed, if at all, before this
	// field could record when, so 0 ("unknown") is correct with no backfill possible - the sweep
	// treats that as ineligible via Closed rather than assuming it happened at the epoch. Same
	// idempotency guard as the v17 step above.
	if currentDbVersion < 26 {
		if !p.columnExists("UploadRequests", "ClosedAt") {
			err := p.rawSqlite(`ALTER TABLE UploadRequests ADD COLUMN "ClosedAt" INTEGER NOT NULL DEFAULT 0;`)
			helper.Check(err)
		}
	}
	// The folder as the unit of sharing: PasswordHash, ExpireAt, UnlimitedTime, DownloadsRemaining
	// and UnlimitedDownloads move from being inferred off member files (see the removed
	// isValidFolderPassword member scan) onto FileBundles itself. Same idempotency guard as the
	// v17 step above. The backfill below derives every existing bundle's values from its current
	// members (models.File.IsBundleMember) and needs no master key - see
	// models.DeriveBundleSettingsFromMembers for the merge rule used when members disagree - so,
	// unlike the name migration, it runs directly in the ladder instead of waiting for an unseal.
	if currentDbVersion < 27 {
		if !p.columnExists("FileBundles", "PasswordHash") {
			err := p.rawSqlite(`ALTER TABLE FileBundles ADD COLUMN "PasswordHash" TEXT NOT NULL DEFAULT '';
			ALTER TABLE FileBundles ADD COLUMN "ExpireAt" INTEGER NOT NULL DEFAULT 0;
			ALTER TABLE FileBundles ADD COLUMN "UnlimitedTime" INTEGER NOT NULL DEFAULT 0;
			ALTER TABLE FileBundles ADD COLUMN "DownloadsRemaining" INTEGER NOT NULL DEFAULT 0;
			ALTER TABLE FileBundles ADD COLUMN "UnlimitedDownloads" INTEGER NOT NULL DEFAULT 0;`)
			helper.Check(err)
		}
		p.backfillBundleSettingsFromMembers()
	}
	// The download window: the timestamp the most recent window opened on a file and on a folder,
	// so access can end at whichever comes first, the resource's own expiry or the close of its
	// window (see models.DownloadAccess). Every row that already exists gets 0, "never opened",
	// which is closed under any leeway - so an upgrade with GOKAPI_DOWNLOAD_LEEWAY unset behaves
	// exactly as before. Same idempotency guard as the v17 step above.
	if currentDbVersion < 28 {
		if !p.columnExists("FileMetaData", "WindowOpenedAt") {
			err := p.rawSqlite(`ALTER TABLE FileMetaData ADD COLUMN "WindowOpenedAt" INTEGER NOT NULL DEFAULT 0;`)
			helper.Check(err)
		}
		if !p.columnExists("FileBundles", "WindowOpenedAt") {
			err := p.rawSqlite(`ALTER TABLE FileBundles ADD COLUMN "WindowOpenedAt" INTEGER NOT NULL DEFAULT 0;`)
			helper.Check(err)
		}
	}
	// A folder its owner deleted outlives the deletion, so its members' retained rows still have
	// something to be grouped under (see models.FileBundle.DeletedAt). Every row that already
	// exists is a live folder by definition - it was never deleted, because a deleted one used to
	// be removed outright - so 0 is correct with no backfill needed, the same reasoning as the v24
	// step's DisposedAt. Same idempotency guard as the v17 step above.
	if currentDbVersion < 29 {
		if !p.columnExists("FileBundles", "DeletedAt") {
			err := p.rawSqlite(`ALTER TABLE FileBundles ADD COLUMN "DeletedAt" INTEGER NOT NULL DEFAULT 0;`)
			helper.Check(err)
		}
	}
}

// grantGuestUploadPermissionV12 grants models.UserPermGuestUploads to every user the v12 step
// covers: all of them if the instance is configured to hand the permission out by default,
// otherwise only the admins. Written against the Users table as it stood at v12 rather than
// through GetAllUsers and SaveUser, which name the AuthProvider and OidcSubject columns the v17
// step adds five steps later - see the note above Upgrade.
func (p DatabaseProvider) grantGuestUploadPermissionV12(grantToEveryUser bool) {
	if grantToEveryUser {
		//goland:noinspection SqlWithoutWhere
		_, err := p.sqliteDb.Exec("UPDATE Users SET Permissions = Permissions | ?", models.UserPermGuestUploads)
		helper.Check(err)
		return
	}
	_, err := p.sqliteDb.Exec("UPDATE Users SET Permissions = Permissions | ? WHERE Userlevel = ? OR Userlevel = ?",
		models.UserPermGuestUploads, models.UserLevelSuperAdmin, models.UserLevelAdmin)
	helper.Check(err)
}

// deleteSystemApiKeysV12 removes the system API keys that the v12 step retires. The expiry
// condition is the one GetAllApiKeys applies, kept verbatim so that an already expired system key
// is left in place here exactly as it was before - it is invisible to the application either way
// and cleanApiKeys collects it later.
func (p DatabaseProvider) deleteSystemApiKeysV12() {
	_, err := p.sqliteDb.Exec("DELETE FROM ApiKeys WHERE IsSystemKey = 1 AND (Expiry == 0 OR Expiry > ?)",
		currentTime().Unix())
	helper.Check(err)
}

// deleteSvgHotlinksV14 deletes every hotlink that points at an SVG file or at no file at all, and
// clears the HotlinkId of the files it unlinks - the v14 step. Reads FileMetaData.Name, which at
// v14 is still the plaintext column the v22 step replaces with NameEncrypted, rather than going
// through GetMetaDataById and SaveMetaData, which name every column the current schema has - see
// the note above Upgrade. Every row is collected before anything is written, so the read is not
// left open across the writes.
func (p DatabaseProvider) deleteSvgHotlinksV14() {
	rows, err := p.sqliteDb.Query(`SELECT Hotlinks.Id, Hotlinks.FileId, FileMetaData.Name, FileMetaData.ContentType
		FROM Hotlinks LEFT JOIN FileMetaData ON FileMetaData.Id = Hotlinks.FileId`)
	helper.Check(err)
	var hotlinksToDelete, filesToUnlink []string
	for rows.Next() {
		var hotlinkId, fileId string
		var name, contentType sql.NullString
		err = rows.Scan(&hotlinkId, &fileId, &name, &contentType)
		helper.Check(err)
		// The join found no file, so the hotlink is dangling and goes regardless of its name.
		if !name.Valid {
			hotlinksToDelete = append(hotlinksToDelete, hotlinkId)
			continue
		}
		if strings.HasSuffix(strings.ToLower(name.String), ".svg") ||
			strings.HasPrefix(strings.ToLower(contentType.String), "image/svg") {
			hotlinksToDelete = append(hotlinksToDelete, hotlinkId)
			filesToUnlink = append(filesToUnlink, fileId)
		}
	}
	helper.Check(rows.Err())
	rows.Close()

	for _, hotlinkId := range hotlinksToDelete {
		_, err = p.sqliteDb.Exec("DELETE FROM Hotlinks WHERE Id = ?", hotlinkId)
		helper.Check(err)
	}
	for _, fileId := range filesToUnlink {
		_, err = p.sqliteDb.Exec("UPDATE FileMetaData SET HotlinkId = '' WHERE Id = ?", fileId)
		helper.Check(err)
	}
}

// backfillBundleSettingsFromMembers derives every existing bundle's PasswordHash, ExpireAt,
// UnlimitedTime, DownloadsRemaining and UnlimitedDownloads from its current members and writes
// them - see models.DeriveBundleSettingsFromMembers for the merge rule. Deterministic in its
// members, so re-running this (e.g. a crash-recovery replay of the v27 step, the same scenario
// TestDatabaseProvider_UpgradeV17Idempotent covers for the v17 step) reproduces the same values
// rather than drifting.
//
// The member scan names only the columns FileMetaData has at v27 instead of calling
// GetAllMetadata, which also selects WindowOpenedAt - a column the v28 step adds one step after
// this one runs - and the write is an UPDATE of the five derived columns instead of a
// SaveFileBundle round trip, so the bundle's name is not rewritten by a migration that has no
// business touching it. See the note above Upgrade.
func (p DatabaseProvider) backfillBundleSettingsFromMembers() {
	rows, err := p.sqliteDb.Query(`SELECT Id, BundleId, PasswordHash, ExpireAt, UnlimitedTime, DownloadsRemaining,
		UnlimitedDownloads, UploadDate, PendingDeletion, DisposedAt, UploadRequestId
		FROM FileMetaData WHERE BundleId != ''`)
	helper.Check(err)
	membersByBundle := make(map[string][]models.File)
	for rows.Next() {
		var file models.File
		var unlimitedTime, unlimitedDownloads int
		err = rows.Scan(&file.Id, &file.BundleId, &file.PasswordHash, &file.ExpireAt, &unlimitedTime,
			&file.DownloadsRemaining, &unlimitedDownloads, &file.UploadDate, &file.PendingDeletion,
			&file.DisposedAt, &file.UploadRequestId)
		helper.Check(err)
		file.UnlimitedTime = unlimitedTime == 1
		file.UnlimitedDownloads = unlimitedDownloads == 1
		if !file.IsBundleMember(file.BundleId) {
			continue
		}
		membersByBundle[file.BundleId] = append(membersByBundle[file.BundleId], file)
	}
	helper.Check(rows.Err())
	rows.Close()

	bundleIds := make([]string, 0)
	rows, err = p.sqliteDb.Query("SELECT id FROM FileBundles")
	helper.Check(err)
	for rows.Next() {
		var bundleId string
		err = rows.Scan(&bundleId)
		helper.Check(err)
		bundleIds = append(bundleIds, bundleId)
	}
	helper.Check(rows.Err())
	rows.Close()

	for _, bundleId := range bundleIds {
		passwordHash, expireAt, unlimitedTime, downloadsRemaining, unlimitedDownloads :=
			models.DeriveBundleSettingsFromMembers(membersByBundle[bundleId])
		_, err = p.sqliteDb.Exec(`UPDATE FileBundles SET PasswordHash = ?, ExpireAt = ?, UnlimitedTime = ?,
			DownloadsRemaining = ?, UnlimitedDownloads = ? WHERE id = ?`,
			passwordHash, expireAt, boolToInt(unlimitedTime), downloadsRemaining, boolToInt(unlimitedDownloads), bundleId)
		helper.Check(err)
	}
}

// boolToInt maps a bool onto the 0/1 integer SQLite stores it as.
func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

// legacyNameColumns returns the additional column and value lists an INSERT has to carry for the
// given table's pre-encryption plaintext name columns, for as long as those columns are still
// present.
//
// FileMetaData.Name and FileBundles.name were created TEXT NOT NULL with no default, and
// MigratePlaintextFileNames only reads and drops them once the instance has been unsealed - which
// at an Input encryption level happens long after the first write of a boot, and never at all on
// an instance that is left sealed. A row inserted before that point therefore has to supply a
// value for them, and an empty string is the only honest one: the row's real name is already in
// the encrypted column, and the migration only ever reads a plaintext name for rows whose
// encrypted column is still NULL.
//
// Rows that already exist are not touched, because the saves that use this insert with
// ON CONFLICT DO UPDATE over the columns they own rather than INSERT OR REPLACE. INSERT OR REPLACE
// deletes the old row and writes a new one, which blanks exactly these columns - and for a row
// that has not been migrated yet, the plaintext column is the only copy of the name there is.
// SaveFileRequest cannot use this, because UploadRequests has a second unique column; see the
// comment there.
func (p DatabaseProvider) legacyNameColumns(table string, columns ...string) (string, string) {
	var extraColumns, extraValues string
	for _, column := range columns {
		if p.columnExists(table, column) {
			extraColumns = extraColumns + `, "` + column + `"`
			extraValues = extraValues + `, ''`
		}
	}
	return extraColumns, extraValues
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
			"DisposedAt"	INTEGER NOT NULL DEFAULT 0,
			"DisposalReason"	INTEGER NOT NULL DEFAULT 0,
			"WindowOpenedAt"	INTEGER NOT NULL DEFAULT 0,
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
			"NameEncrypted"	BLOB,
			"userid"	INTEGER NOT NULL,
			"expiry"	INTEGER NOT NULL,
			"maxFiles"	INTEGER NOT NULL,
			"maxSize"	INTEGER NOT NULL,
			"creation"	INTEGER NOT NULL,
			"apiKey"	TEXT NOT NULL UNIQUE,
			"NoteEncrypted"	BLOB,
			"closed"	INTEGER NOT NULL DEFAULT 0,
			"Collaborators"	TEXT NOT NULL DEFAULT '[]',
			"ClosedAt"	INTEGER NOT NULL DEFAULT 0,
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
			"NameEncrypted"	BLOB,
			"userid"	INTEGER NOT NULL,
			"creationdate"	INTEGER NOT NULL,
			"EncryptedSharePassword"	BLOB,
			"PasswordHash"	TEXT NOT NULL DEFAULT '',
			"ExpireAt"	INTEGER NOT NULL DEFAULT 0,
			"UnlimitedTime"	INTEGER NOT NULL DEFAULT 0,
			"DownloadsRemaining"	INTEGER NOT NULL DEFAULT 0,
			"UnlimitedDownloads"	INTEGER NOT NULL DEFAULT 0,
			"WindowOpenedAt"	INTEGER NOT NULL DEFAULT 0,
			"DeletedAt"	INTEGER NOT NULL DEFAULT 0,
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
