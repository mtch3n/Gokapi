//go:build test

package sqlite

import (
	"bytes"
	"database/sql"
	"encoding/gob"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/test"
)

// This file walks the upgrade ladder from every stored schema version Upgrade still accepts, which
// is the coverage that was missing when a v27 step called current model code, read a column the
// v28 step had not added yet and left a production database half migrated: every migration test
// there was either started from a database createNewDatabase had just written at the current
// version, or replayed a single step against one. Neither builds an old schema, so neither can
// tell whether a step reads something its own version does not have.
//
// A fixture here is therefore a real database at an old version, built from DDL frozen as that
// version shipped, not a current one with its version number rewound.

// ladderOldestSupportedVersion is the oldest stored version Upgrade migrates rather than refusing:
// below it, the first step of Upgrade prints an error and exits.
const ladderOldestSupportedVersion = 10

// schemaV10 is createNewDatabase exactly as it stood when DatabaseSchemeVersion was 10 (Gokapi
// v2.2.0), which is the oldest database the ladder still accepts. Frozen: it describes a schema
// that shipped years ago and must never be edited to follow the current one.
const schemaV10 = `CREATE TABLE "ApiKeys" (
			"Id"	TEXT NOT NULL UNIQUE,
			"FriendlyName"	TEXT NOT NULL,
			"LastUsed"	INTEGER NOT NULL,
			"Permissions"	INTEGER NOT NULL DEFAULT 0,
			"Expiry"	INTEGER,
			"IsSystemKey"	INTEGER,
			"UserId" INTEGER NOT NULL,
			"PublicId" TEXT NOT NULL UNIQUE ,
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
			"Name"	TEXT NOT NULL,
			"Size"	TEXT NOT NULL,
			"SHA1"	TEXT NOT NULL,
			"ExpireAt"	INTEGER NOT NULL,
			"SizeBytes"	INTEGER NOT NULL,
			"ExpireAtString"	TEXT NOT NULL,
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
			PRIMARY KEY("Id" AUTOINCREMENT)
		);`

// schemaLadderStep is the DDL that turns a database at the previous schema version into one at
// Version, copied from the matching step of Upgrade with its idempotency guards left off - a
// fixture is built once, from scratch, so it never re-runs a step.
//
// This is deliberately a second, hand-maintained copy of that DDL rather than a call into Upgrade:
// a fixture built by the code under test could only ever agree with it. Keeping the two apart is
// what lets TestSchemaLadderMatchesCreateNewDatabase compare the schema this ladder produces
// against the one createNewDatabase writes and notice when they have drifted apart.
type schemaLadderStep struct {
	Version int
	Ddl     string
}

// schemaLadder holds one entry per version above schemaV10, in order and with no gaps. A version
// whose step changed no tables carries an empty Ddl rather than being left out, so that the list
// reads as the full history and a missing version is unambiguously a mistake.
//
// Adding a step to Upgrade means adding its DDL here: TestSchemaLadderCoversEveryVersion fails
// while the last entry below is behind DatabaseSchemeVersion, and buildLadderDatabase refuses to
// claim it built a version this list does not reach.
var schemaLadder = []schemaLadderStep{
	{11, `ALTER TABLE FileMetaData DROP COLUMN ExpireAtString;`},
	{12, `ALTER TABLE FileMetaData ADD COLUMN "UploadRequestId" TEXT NOT NULL DEFAULT '';
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
		);`},
	{13, `CREATE TABLE "Statistics" (
				"id"	INTEGER NOT NULL,
				"type"	INTEGER NOT NULL UNIQUE,
				"value"	INTEGER,
				PRIMARY KEY("id" AUTOINCREMENT)
			);`},
	// v14 removes hotlinks for SVG files and v15 wipes sessions; neither changes the schema.
	{14, ``},
	{15, ``},
	{16, `ALTER TABLE FileMetaData ADD COLUMN "BundleId" TEXT NOT NULL DEFAULT '';
		CREATE TABLE "FileBundles" (
			"id"	TEXT NOT NULL UNIQUE,
			"name"	TEXT NOT NULL,
			"userid"	INTEGER NOT NULL,
			"creationdate"	INTEGER NOT NULL,
			PRIMARY KEY("id")
		);`},
	{17, `ALTER TABLE Users ADD COLUMN "AuthProvider" TEXT NOT NULL DEFAULT 'internal';
		ALTER TABLE Users ADD COLUMN "OidcSubject" TEXT NOT NULL DEFAULT '';`},
	{18, `ALTER TABLE Sessions ADD COLUMN "IsOauth" INTEGER NOT NULL DEFAULT 0;`},
	{19, `CREATE TABLE "ShareRecipients" (
				"id"			INTEGER NOT NULL,
				"email"			TEXT NOT NULL UNIQUE,
				"createdat"		INTEGER NOT NULL,
				"lastloginat"	INTEGER NOT NULL DEFAULT 0,
				"isblocked"		INTEGER NOT NULL DEFAULT 0,
				PRIMARY KEY("id" AUTOINCREMENT)
			);
			CREATE TABLE "ShareGrants" (
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
			CREATE INDEX "idx_sharelogintokens_recipient" ON "ShareLoginTokens" ("recipientid");`},
	{20, `ALTER TABLE FileMetaData ADD COLUMN "EncryptedSharePassword" BLOB;
		ALTER TABLE FileBundles ADD COLUMN "EncryptedSharePassword" BLOB;`},
	{21, `ALTER TABLE UploadRequests ADD COLUMN "closed" INTEGER NOT NULL DEFAULT 0;`},
	{22, `ALTER TABLE FileMetaData ADD COLUMN "NameEncrypted" BLOB;`},
	{23, `ALTER TABLE FileBundles ADD COLUMN "NameEncrypted" BLOB;
		ALTER TABLE UploadRequests ADD COLUMN "NameEncrypted" BLOB;
		ALTER TABLE UploadRequests ADD COLUMN "NoteEncrypted" BLOB;`},
	{24, `ALTER TABLE FileMetaData ADD COLUMN "DisposedAt" INTEGER NOT NULL DEFAULT 0;
		ALTER TABLE FileMetaData ADD COLUMN "DisposalReason" INTEGER NOT NULL DEFAULT 0;`},
	{25, `ALTER TABLE UploadRequests ADD COLUMN "Collaborators" TEXT NOT NULL DEFAULT '[]';`},
	{26, `ALTER TABLE UploadRequests ADD COLUMN "ClosedAt" INTEGER NOT NULL DEFAULT 0;`},
	{27, `ALTER TABLE FileBundles ADD COLUMN "PasswordHash" TEXT NOT NULL DEFAULT '';
		ALTER TABLE FileBundles ADD COLUMN "ExpireAt" INTEGER NOT NULL DEFAULT 0;
		ALTER TABLE FileBundles ADD COLUMN "UnlimitedTime" INTEGER NOT NULL DEFAULT 0;
		ALTER TABLE FileBundles ADD COLUMN "DownloadsRemaining" INTEGER NOT NULL DEFAULT 0;
		ALTER TABLE FileBundles ADD COLUMN "UnlimitedDownloads" INTEGER NOT NULL DEFAULT 0;`},
	{28, `ALTER TABLE FileMetaData ADD COLUMN "WindowOpenedAt" INTEGER NOT NULL DEFAULT 0;
		ALTER TABLE FileBundles ADD COLUMN "WindowOpenedAt" INTEGER NOT NULL DEFAULT 0;`},
	{29, `ALTER TABLE FileBundles ADD COLUMN "DeletedAt" INTEGER NOT NULL DEFAULT 0;`},
}

// The fixture rows every ladder database is seeded with. All of them predate the encrypted name
// columns, so their names sit in the plaintext columns that MigratePlaintextFileNames converts
// after an unseal - the state the folder whose name was destroyed in production was in.
const (
	ladderUserName          = "ladderadmin"
	ladderNormalKeyId       = "ladderNormalKey"
	ladderNormalKeyName     = "Ladder key"
	ladderSystemKeyId       = "ladderSystemKey"
	ladderSvgFileId         = "ladderSvgFile"
	ladderSvgFileName       = "logo.svg"
	ladderSvgHotlinkId      = "ladderSvgHotlink"
	ladderDanglingHotlinkId = "ladderDanglingHotlink"
	ladderMemberFileId      = "ladderMemberFile"
	ladderMemberFileName    = "annual-report.pdf"
	ladderMemberHash        = "laddermemberhash"
	ladderBundleId          = "ladderBundle"
	ladderBundleName        = "Quarterly reports 2026"
	ladderRequestId         = "ladderRequest"
	ladderRequestName       = "Vendor invoices"
	ladderRequestNote       = "please zip them"
	ladderRecipientEmail    = "recipient@ladder.test"
)

// TestSchemaLadderCoversEveryVersion is the reason a future step cannot be added without
// extending this file. The list above is written out by hand, one literal entry per version, so it
// cannot follow DatabaseSchemeVersion on its own: raising that constant for a v29 step while
// leaving the list at v28 fails here, and the failure names the version that has no fixture.
func TestSchemaLadderCoversEveryVersion(t *testing.T) {
	test.IsEqualInt(t, schemaLadder[0].Version, ladderOldestSupportedVersion+1)
	for i, step := range schemaLadder {
		test.IsEqualInt(t, step.Version, ladderOldestSupportedVersion+1+i)
	}
	test.IsEqualInt(t, schemaLadder[len(schemaLadder)-1].Version, DatabaseSchemeVersion)
}

// TestSchemaLadderMatchesCreateNewDatabase checks the frozen DDL above against the schema
// createNewDatabase writes, so the fixtures cannot quietly describe a database that no longer
// exists. Only the set of columns per table is compared, not their order: SQLite appends an
// ALTER TABLE ADD COLUMN at the end of a table, so an upgraded database legitimately orders its
// columns differently from a fresh one - the reason metaDataColumns and fileBundleColumns list
// their columns explicitly instead of using SELECT *.
//
// The pre-encryption plaintext name columns are the one expected difference. A fresh database has
// never had them; an upgraded one keeps them until MigratePlaintextFileNames converts and drops
// them, which needs a master key and so cannot happen in the ladder.
func TestSchemaLadderMatchesCreateNewDatabase(t *testing.T) {
	upgradedPath := "./test/ladder/gokapi_schema_upgraded.sqlite"
	buildLadderDatabase(t, upgradedPath, DatabaseSchemeVersion)
	upgraded, err := New(models.DbConnection{HostUrl: upgradedPath})
	test.IsNil(t, err)
	defer upgraded.Close()

	fresh, err := New(models.DbConnection{HostUrl: "./test/ladder/gokapi_schema_fresh.sqlite"})
	test.IsNil(t, err)
	defer fresh.Close()

	legacyPlaintextColumns := map[string][]string{
		"FileMetaData":   {"Name"},
		"FileBundles":    {"name"},
		"UploadRequests": {"name", "note"},
	}
	for _, table := range ladderTableNames(t, fresh.sqliteDb) {
		freshColumns := ladderColumnNames(t, fresh.sqliteDb, table)
		upgradedColumns := ladderColumnNames(t, upgraded.sqliteDb, table)
		for _, legacy := range legacyPlaintextColumns[table] {
			test.IsEqualBool(t, slices.Contains(upgradedColumns, legacy), true)
			upgradedColumns = slices.DeleteFunc(upgradedColumns, func(column string) bool {
				return column == legacy
			})
		}
		test.IsEqual(t, upgradedColumns, freshColumns)
	}
	test.IsEqual(t, ladderTableNames(t, upgraded.sqliteDb), ladderTableNames(t, fresh.sqliteDb))
}

// TestUpgradeFromEverySchemaVersion builds a database at every version the ladder accepts, runs
// the whole ladder against it and checks that it arrives at the current version with its data
// intact. Upgrading from 26 is the path production took; upgrading from 10 through 13 exercises
// the three steps that read rows rather than only altering tables.
func TestUpgradeFromEverySchemaVersion(t *testing.T) {
	for version := ladderOldestSupportedVersion; version <= schemaLadder[len(schemaLadder)-1].Version; version++ {
		t.Run(fmt.Sprintf("from_v%d", version), func(t *testing.T) {
			path := fmt.Sprintf("./test/ladder/gokapi_from_v%d.sqlite", version)
			buildLadderDatabase(t, path, version)
			instance, err := New(models.DbConnection{HostUrl: path})
			test.IsNil(t, err)
			defer instance.Close()

			test.IsEqualInt(t, instance.GetDbVersion(), version)
			// The two calls database.Upgrade makes, in its order: the version is only stored once
			// the whole ladder has run, which is why every step has to be safe to replay.
			instance.Upgrade(instance.GetDbVersion())
			instance.SetDbVersion(instance.GetSchemaVersion())
			test.IsEqualInt(t, instance.GetDbVersion(), instance.GetSchemaVersion())

			assertLadderDataSurvived(t, instance, version)
		})
	}
}

// TestUpgradeV12GrantsGuestUploadToEveryUser covers the other half of the v12 step, which
// TestUpgradeFromEverySchemaVersion cannot reach: with GUEST_UPLOAD_BY_DEFAULT set, the guest
// upload permission goes to every user rather than only to the admins.
func TestUpgradeV12GrantsGuestUploadToEveryUser(t *testing.T) {
	t.Setenv("GOKAPI_GUEST_UPLOAD_BY_DEFAULT", "true")
	path := "./test/ladder/gokapi_guest_upload_default.sqlite"
	buildLadderDatabase(t, path, 11)
	instance, err := New(models.DbConnection{HostUrl: path})
	test.IsNil(t, err)
	defer instance.Close()

	_, err = instance.sqliteDb.Exec(`INSERT INTO Users (Name, Password, Permissions, Userlevel, LastOnline, ResetPassword)
		VALUES (?, ?, ?, ?, ?, ?)`, "ladderuser", "hashedpassword", 1, models.UserLevelUser, 0, 0)
	test.IsNil(t, err)

	instance.Upgrade(instance.GetDbVersion())
	instance.SetDbVersion(instance.GetSchemaVersion())

	users := instance.GetAllUsers()
	test.IsEqualInt(t, len(users), 2)
	for _, user := range users {
		// 259 is the admin's 3 and 257 the plain user's 1, each with UserPermGuestUploads (256).
		if user.Name == ladderUserName {
			test.IsEqualInt(t, int(user.Permissions), 259)
			continue
		}
		test.IsEqualInt(t, int(user.Permissions), 257)
	}
}

// TestUpgradeFromCurrentVersionChangesNothing is the check that matters for a deployment onto a
// database that is already at the current version, which is where production sits now: Upgrade
// must touch neither the schema nor a single row. Both shapes a current database can have are
// covered - one that came up the ladder and still carries the legacy plaintext columns, and one
// createNewDatabase wrote.
func TestUpgradeFromCurrentVersionChangesNothing(t *testing.T) {
	upgradedPath := "./test/ladder/gokapi_noop_upgraded.sqlite"
	buildLadderDatabase(t, upgradedPath, DatabaseSchemeVersion)
	upgraded, err := New(models.DbConnection{HostUrl: upgradedPath})
	test.IsNil(t, err)
	defer upgraded.Close()

	before := ladderSnapshot(t, upgraded.sqliteDb)
	upgraded.Upgrade(upgraded.GetDbVersion())
	test.IsEqualString(t, ladderSnapshot(t, upgraded.sqliteDb), before)

	fresh, err := New(models.DbConnection{HostUrl: "./test/ladder/gokapi_noop_fresh.sqlite"})
	test.IsNil(t, err)
	defer fresh.Close()
	fresh.SaveFileBundle(models.FileBundle{Id: ladderBundleId, Name: ladderBundleName, UserId: 1,
		CreationDate: 1700000000, DownloadsRemaining: 4, ExpireAt: 1800000000})
	fresh.SaveMetaData(models.File{Id: ladderMemberFileId, Name: ladderMemberFileName, SHA1: "a",
		BundleId: ladderBundleId, PasswordHash: ladderMemberHash, ExpireAt: 1800000000,
		DownloadsRemaining: 4, UploadDate: 100})

	before = ladderSnapshot(t, fresh.sqliteDb)
	fresh.Upgrade(fresh.GetDbVersion())
	test.IsEqualString(t, ladderSnapshot(t, fresh.sqliteDb), before)
}

// TestSaveKeepsLegacyPlaintextNames covers the second failure the outage exposed, once the
// migration ordering had been worked around by hand: a row whose name is still in the
// pre-encryption plaintext column has to stay writable, and has to keep that name. INSERT OR
// REPLACE deletes the row and writes a new one, so it blanked a column it never named - which on
// a database created at v16 is TEXT NOT NULL with no default, so the write failed outright, and
// with a default it would silently have thrown the only copy of the name away.
func TestSaveKeepsLegacyPlaintextNames(t *testing.T) {
	path := "./test/ladder/gokapi_legacy_names.sqlite"
	buildLadderDatabase(t, path, DatabaseSchemeVersion)
	instance, err := New(models.DbConnection{HostUrl: path})
	test.IsNil(t, err)
	defer instance.Close()

	// Every one of these is a write the application makes while the names are still unmigrated.
	bundle, ok := instance.GetFileBundle(ladderBundleId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, bundle.Name, "")
	bundle.DownloadsRemaining = 7
	instance.SaveFileBundle(bundle)

	file, ok := instance.GetMetaDataById(ladderMemberFileId)
	test.IsEqualBool(t, ok, true)
	file.PendingDeletion = 1234
	instance.SaveMetaData(file)

	request, ok := instance.GetFileRequest(ladderRequestId)
	test.IsEqualBool(t, ok, true)
	request.Closed = true
	instance.SaveFileRequest(request)

	// A new row, inserted while those NOT NULL columns are still there and still have no default.
	instance.SaveFileBundle(models.FileBundle{Id: "ladderNewBundle", Name: "New folder", UserId: 1,
		CreationDate: 1700000000})

	// The writes landed,
	bundle, ok = instance.GetFileBundle(ladderBundleId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt(t, bundle.DownloadsRemaining, 7)
	file, ok = instance.GetMetaDataById(ladderMemberFileId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualInt64(t, file.PendingDeletion, 1234)
	request, ok = instance.GetFileRequest(ladderRequestId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualBool(t, request.Closed, true)

	// and none of them touched the plaintext column holding the name.
	test.IsEqualString(t, ladderLegacyValue(t, instance, "FileBundles", "name", ladderBundleId), ladderBundleName)
	test.IsEqualString(t, ladderLegacyValue(t, instance, "FileMetaData", "Name", ladderMemberFileId), ladderMemberFileName)
	test.IsEqualString(t, ladderLegacyValue(t, instance, "UploadRequests", "name", ladderRequestId), ladderRequestName)
	test.IsEqualString(t, ladderLegacyValue(t, instance, "UploadRequests", "note", ladderRequestId), ladderRequestNote)

	// So the migration that runs after an unseal still finds those names, which is precisely what
	// was lost in production: the folder whose plaintext name a write had already blanked came
	// back from the unseal named after an empty string.
	//
	// The note is left out of this last check on purpose. SaveFileRequest above stored an
	// encrypted empty note, because an empty note is a value an owner can legitimately set and
	// encryptNoteForSave will not second-guess it - see TestClearingNoteActuallyClears. Reaching
	// that state before the migration takes a save on an unsealed instance whose notes have not
	// been converted yet, which the server never does: Main runs the migration immediately after
	// connecting the database, before the webserver accepts a request.
	instance.MigratePlaintextFileNames()
	bundle, ok = instance.GetFileBundle(ladderBundleId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, bundle.Name, ladderBundleName)
	file, ok = instance.GetMetaDataById(ladderMemberFileId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, file.Name, ladderMemberFileName)
	request, ok = instance.GetFileRequest(ladderRequestId)
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, request.Name, ladderRequestName)
}

// assertLadderDataSurvived checks the seeded rows against what the steps between fromVersion and
// the current version are supposed to have done to them. The expectations are written as the
// literal values the fixture was seeded with, so that a step which silently stops running is a
// failure rather than a test that agrees with whatever it finds.
func assertLadderDataSurvived(t *testing.T, instance DatabaseProvider, fromVersion int) {
	t.Helper()

	users := instance.GetAllUsers()
	test.IsEqualInt(t, len(users), 1)
	test.IsEqualString(t, users[0].Name, ladderUserName)
	// The v17 step backfills this, so it is set no matter which version the database started at.
	test.IsEqualString(t, users[0].AuthProvider, models.AuthProviderInternal)
	// The fixture user is an admin with UserPermReplaceUploads|UserPermListOtherUploads, so the
	// v12 step adds UserPermGuestUploads (256) to their 3.
	expectedPermissions := 3
	if fromVersion < 12 {
		expectedPermissions = 259
	}
	test.IsEqualInt(t, int(users[0].Permissions), expectedPermissions)

	// The v12 step retires system API keys and leaves every other key alone.
	apiKeys := instance.GetAllApiKeys()
	_, systemKeyExists := apiKeys[ladderSystemKeyId]
	test.IsEqualBool(t, systemKeyExists, fromVersion >= 12)
	normalKey, ok := apiKeys[ladderNormalKeyId]
	test.IsEqualBool(t, ok, true)
	test.IsEqualString(t, normalKey.FriendlyName, ladderNormalKeyName)

	// The v14 step deletes the hotlink on the SVG file and the one pointing at no file at all.
	hotlinks := instance.GetAllHotlinks()
	test.IsEqualBool(t, slices.Contains(hotlinks, ladderSvgHotlinkId), fromVersion >= 14)
	test.IsEqualBool(t, slices.Contains(hotlinks, ladderDanglingHotlinkId), fromVersion >= 14)

	files := instance.GetAllMetadata()
	test.IsEqualInt(t, len(files), 2)
	expectedHotlinkId := ladderSvgHotlinkId
	if fromVersion < 14 {
		expectedHotlinkId = ""
	}
	test.IsEqualString(t, files[ladderSvgFileId].HotlinkId, expectedHotlinkId)
	test.IsEqualString(t, files[ladderSvgFileId].ContentType, "image/svg+xml")

	member := files[ladderMemberFileId]
	test.IsEqualString(t, member.PasswordHash, ladderMemberHash)
	test.IsEqualInt64(t, member.ExpireAt, 1800000000)
	test.IsEqualInt(t, member.DownloadsRemaining, 4)
	test.IsEqualInt64(t, member.UploadDate, 100)
	// Never opened, which is what the v28 step gives every row that already existed.
	test.IsEqualInt64(t, member.WindowOpenedAt, 0)
	expectedBundleId := ladderBundleId
	if fromVersion < 16 {
		expectedBundleId = ""
	}
	test.IsEqualString(t, member.BundleId, expectedBundleId)

	bundles := instance.GetAllFileBundles()
	if fromVersion < 16 {
		test.IsEqualInt(t, len(bundles), 0)
	} else {
		test.IsEqualInt(t, len(bundles), 1)
		test.IsEqualString(t, bundles[0].Id, ladderBundleId)
		test.IsEqualInt(t, bundles[0].UserId, 1)
		test.IsEqualInt64(t, bundles[0].CreationDate, 1700000000)
		// The v27 step derives the bundle's settings from its one member. A database that already
		// stored 27 or more ran that step before this fixture was built, so its bundle keeps the
		// defaults the v27 columns were added with.
		if fromVersion < 27 {
			test.IsEqualString(t, bundles[0].PasswordHash, ladderMemberHash)
			test.IsEqualInt64(t, bundles[0].ExpireAt, 1800000000)
			test.IsEqualInt(t, bundles[0].DownloadsRemaining, 4)
		} else {
			test.IsEqualString(t, bundles[0].PasswordHash, "")
			test.IsEqualInt64(t, bundles[0].ExpireAt, 0)
			test.IsEqualInt(t, bundles[0].DownloadsRemaining, 0)
		}
		test.IsEqualBool(t, bundles[0].UnlimitedTime, false)
		test.IsEqualBool(t, bundles[0].UnlimitedDownloads, false)
		test.IsEqualInt64(t, bundles[0].WindowOpenedAt, 0)
		// Still in the plaintext column: nothing in the ladder can encrypt it.
		test.IsEqualString(t, bundles[0].Name, "")
	}

	if fromVersion >= 12 {
		request, requestExists := instance.GetFileRequest(ladderRequestId)
		test.IsEqualBool(t, requestExists, true)
		test.IsEqualInt(t, request.MaxFiles, 5)
		test.IsEqualInt(t, request.MaxSize, 20)
		test.IsEqualInt64(t, request.Expiry, 1900000000)
		test.IsEqualBool(t, request.Closed, false)
		test.IsEqualInt64(t, request.ClosedAt, 0)
		test.IsEqualInt(t, len(request.CollaboratorIds()), 0)
	}

	if fromVersion >= 19 {
		recipients := instance.GetAllShareRecipients()
		test.IsEqualInt(t, len(recipients), 1)
		test.IsEqualString(t, recipients[0].Email, ladderRecipientEmail)
		grants := instance.GetShareGrants(0, ladderMemberFileId)
		test.IsEqualInt(t, len(grants), 1)
		test.IsEqualInt(t, grants[0].DownloadsAllowed, 3)
	}

	// The plaintext names an older version stored are all still readable afterwards, which is the
	// point of the ladder never writing to those columns: the migration that converts them only
	// runs once the instance has been unsealed, long after Upgrade is done.
	instance.MigratePlaintextFileNames()
	test.IsEqualString(t, instance.GetAllMetadata()[ladderMemberFileId].Name, ladderMemberFileName)
	test.IsEqualString(t, instance.GetAllMetadata()[ladderSvgFileId].Name, ladderSvgFileName)
	if fromVersion >= 16 {
		bundle, bundleExists := instance.GetFileBundle(ladderBundleId)
		test.IsEqualBool(t, bundleExists, true)
		test.IsEqualString(t, bundle.Name, ladderBundleName)
	}
	if fromVersion >= 12 {
		request, requestExists := instance.GetFileRequest(ladderRequestId)
		test.IsEqualBool(t, requestExists, true)
		test.IsEqualString(t, request.Name, ladderRequestName)
		test.IsEqualString(t, request.Notes, ladderRequestNote)
	}
}

// buildLadderDatabase writes a database file that is genuinely at the given schema version: the
// v10 schema, then every frozen step up to and including it, then the seed rows and the stored
// version. Nothing here goes through DatabaseProvider, which only ever writes the current schema.
func buildLadderDatabase(t *testing.T, path string, version int) {
	t.Helper()
	err := os.MkdirAll(filepath.Dir(path), 0700)
	test.IsNil(t, err)
	err = os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		test.IsNil(t, err)
	}
	db, err := sql.Open("sqlite", filepath.Clean(path))
	test.IsNil(t, err)
	defer func() {
		test.IsNil(t, db.Close())
	}()

	_, err = db.Exec(schemaV10)
	test.IsNil(t, err)
	reached := ladderOldestSupportedVersion
	for _, step := range schemaLadder {
		if step.Version > version {
			break
		}
		if step.Ddl != "" {
			_, err = db.Exec(step.Ddl)
			test.IsNilWithMessage(t, err, fmt.Sprintf("ladder step to v%d", step.Version))
		}
		reached = step.Version
	}
	// A version with no frozen DDL would otherwise be built as the highest one that has some, and
	// pass while testing nothing.
	test.IsEqualInt(t, reached, version)

	seedLadderData(t, db, version)
	_, err = db.Exec(fmt.Sprintf("PRAGMA user_version = %d;", version))
	test.IsNil(t, err)
}

// seedLadderData inserts the fixture rows, naming only columns that exist at the given version and
// leaving every later column to the default its ALTER TABLE gave it - which is exactly how a real
// database that has been through the ladder carries its old rows forward.
func seedLadderData(t *testing.T, db *sql.DB, version int) {
	t.Helper()
	execLadder := func(query string, args ...any) {
		t.Helper()
		_, err := db.Exec(query, args...)
		test.IsNilWithMessage(t, err, "seeding "+query)
	}

	execLadder(`INSERT INTO Users (Name, Password, Permissions, Userlevel, LastOnline, ResetPassword)
		VALUES (?, ?, ?, ?, ?, ?)`, ladderUserName, "hashedpassword", 3, models.UserLevelAdmin, 0, 0)

	execLadder(`INSERT INTO ApiKeys (Id, FriendlyName, LastUsed, Permissions, Expiry, IsSystemKey, UserId, PublicId)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, ladderNormalKeyId, ladderNormalKeyName, 0, 15, 0, 0, 1, "ladderNormalPublic")
	execLadder(`INSERT INTO ApiKeys (Id, FriendlyName, LastUsed, Permissions, Expiry, IsSystemKey, UserId, PublicId)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, ladderSystemKeyId, "System key", 0, 15, 0, 1, 1, "ladderSystemPublic")

	// FileMetaData.Encryption holds a gob of models.EncryptionInfo, which ToFileModel decodes on
	// every read, so an empty blob would not survive the round trip.
	var encryptionInfo bytes.Buffer
	test.IsNil(t, gob.NewEncoder(&encryptionInfo).Encode(models.EncryptionInfo{}))
	fileColumns := `Id, Name, Size, SHA1, ExpireAt, SizeBytes, DownloadsRemaining, DownloadCount, PasswordHash,
		HotlinkId, ContentType, AwsBucket, Encryption, UnlimitedDownloads, UnlimitedTime, UserId, UploadDate,
		PendingDeletion`
	fileValues := `?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?`
	// ExpireAtString is NOT NULL and only exists at v10; the v11 step drops it.
	if version == ladderOldestSupportedVersion {
		fileColumns += `, ExpireAtString`
		fileValues += `, ''`
	}
	// BundleId arrives with the v16 step, together with the FileBundles table itself.
	memberBundleId := ""
	if version >= 16 {
		fileColumns += `, BundleId`
		fileValues += `, ?`
		memberBundleId = ladderBundleId
	}
	insertFile := `INSERT INTO FileMetaData (` + fileColumns + `) VALUES (` + fileValues + `)`
	svgArgs := []any{ladderSvgFileId, ladderSvgFileName, "1 B", "sha1svg", 1900000000, 1, 5, 0, "",
		ladderSvgHotlinkId, "image/svg+xml", "", encryptionInfo.Bytes(), 0, 0, 1, 50, 0}
	memberArgs := []any{ladderMemberFileId, ladderMemberFileName, "2 B", "sha1member", 1800000000, 2, 4, 0,
		ladderMemberHash, "", "application/pdf", "", encryptionInfo.Bytes(), 0, 0, 1, 100, 0}
	if version >= 16 {
		svgArgs = append(svgArgs, "")
		memberArgs = append(memberArgs, memberBundleId)
	}
	execLadder(insertFile, svgArgs...)
	execLadder(insertFile, memberArgs...)

	execLadder(`INSERT INTO Hotlinks (Id, FileId) VALUES (?, ?)`, ladderSvgHotlinkId, ladderSvgFileId)
	execLadder(`INSERT INTO Hotlinks (Id, FileId) VALUES (?, ?)`, ladderDanglingHotlinkId, "ladderMissingFile")

	execLadder(`INSERT INTO Sessions (Id, RenewAt, ValidUntil, UserId) VALUES (?, ?, ?, ?)`,
		"ladderSession", 1900000000, 1900000000, 1)

	if version >= 12 {
		execLadder(`INSERT INTO UploadRequests (id, name, userid, expiry, maxFiles, maxSize, creation, apiKey, note)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, ladderRequestId, ladderRequestName, 1, 1900000000, 5, 20,
			1700000000, "ladderRequestApiKey", ladderRequestNote)
	}
	if version >= 16 {
		execLadder(`INSERT INTO FileBundles (id, name, userid, creationdate) VALUES (?, ?, ?, ?)`,
			ladderBundleId, ladderBundleName, 1, 1700000000)
	}
	if version >= 19 {
		execLadder(`INSERT INTO ShareRecipients (email, createdat) VALUES (?, ?)`, ladderRecipientEmail, 1700000000)
		execLadder(`INSERT INTO ShareGrants (resourcetype, resourceid, recipientid, grantedat, grantedby, downloadsallowed)
			VALUES (?, ?, ?, ?, ?, ?)`, 0, ladderMemberFileId, 1, 1700000000, 1, 3)
	}
}

// ladderLegacyValue reads a pre-encryption plaintext column directly, which is the only way to see
// it: every model-facing read has already moved on to the encrypted column.
func ladderLegacyValue(t *testing.T, instance DatabaseProvider, table, column, id string) string {
	t.Helper()
	var value string
	row := instance.sqliteDb.QueryRow(fmt.Sprintf(`SELECT "%s" FROM %s WHERE id = ?`, column, table), id)
	test.IsNil(t, row.Scan(&value))
	return value
}

// ladderTableNames returns every table in the database, sorted.
func ladderTableNames(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	test.IsNil(t, err)
	defer rows.Close()
	names := make([]string, 0)
	for rows.Next() {
		var name string
		test.IsNil(t, rows.Scan(&name))
		names = append(names, name)
	}
	test.IsNil(t, rows.Err())
	return names
}

// ladderColumnNames returns the columns of a table, sorted, so that two databases can be compared
// without their column order mattering.
func ladderColumnNames(t *testing.T, db *sql.DB, table string) []string {
	t.Helper()
	rows, err := db.Query(fmt.Sprintf(`PRAGMA table_info("%s");`, table))
	test.IsNil(t, err)
	defer rows.Close()
	names := make([]string, 0)
	for rows.Next() {
		var cid, notNull, pk int
		var name, colType string
		var defaultValue sql.NullString
		test.IsNil(t, rows.Scan(&cid, &name, &colType, &notNull, &defaultValue, &pk))
		names = append(names, name)
	}
	test.IsNil(t, rows.Err())
	sort.Strings(names)
	return names
}

// ladderSnapshot renders the whole database - stored version, schema and every row of every table -
// as one string, so that "nothing changed" can be asserted rather than described. Rows are sorted
// rather than ordered by a key, since the tables here have no single ordering column in common.
func ladderSnapshot(t *testing.T, db *sql.DB) string {
	t.Helper()
	var snapshot strings.Builder
	var userVersion int
	test.IsNil(t, db.QueryRow("PRAGMA user_version;").Scan(&userVersion))
	snapshot.WriteString(fmt.Sprintf("user_version=%d\n", userVersion))

	schemaRows, err := db.Query(`SELECT type, name, IFNULL(sql, '') FROM sqlite_master
		WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name`)
	test.IsNil(t, err)
	defer schemaRows.Close()
	for schemaRows.Next() {
		var objectType, name, statement string
		test.IsNil(t, schemaRows.Scan(&objectType, &name, &statement))
		snapshot.WriteString(objectType + " " + name + ": " + statement + "\n")
	}
	test.IsNil(t, schemaRows.Err())

	for _, table := range ladderTableNames(t, db) {
		snapshot.WriteString("table " + table + "\n")
		for _, row := range ladderTableRows(t, db, table) {
			snapshot.WriteString("  " + row + "\n")
		}
	}
	return snapshot.String()
}

// ladderTableRows renders every row of a table as a sorted list of strings.
func ladderTableRows(t *testing.T, db *sql.DB, table string) []string {
	t.Helper()
	rows, err := db.Query(fmt.Sprintf(`SELECT * FROM "%s"`, table))
	test.IsNil(t, err)
	defer rows.Close()
	columns, err := rows.Columns()
	test.IsNil(t, err)
	rendered := make([]string, 0)
	for rows.Next() {
		values := make([]any, len(columns))
		for i := range values {
			values[i] = new(sql.NullString)
		}
		test.IsNil(t, rows.Scan(values...))
		var line strings.Builder
		for i, column := range columns {
			value := values[i].(*sql.NullString)
			line.WriteString(fmt.Sprintf("%s=%q,%t;", column, value.String, value.Valid))
		}
		rendered = append(rendered, line.String())
	}
	test.IsNil(t, rows.Err())
	sort.Strings(rendered)
	return rendered
}
