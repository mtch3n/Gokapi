// Package applymaxexpiry implements the "apply-max-expiry" CLI command: a one-off, manually
// triggered pass that clamps every existing file and file request to GOKAPI_MAX_EXPIRY.
//
// This is deliberately not a database.Upgrade() ladder step. That ladder runs on every boot,
// which is exactly the surprise the owner rejected for this change: lowering (or newly
// setting) the maximum expiry must never silently rewrite - and so silently mark for deletion
// - files that were uploaded under a looser or absent policy. A file outliving the policy
// until an operator explicitly asks for this command to run is the safe default; there is
// also no schema version bump, since nothing about the stored schema changes.
package applymaxexpiry

import (
	"fmt"
	"os"
	"time"

	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/environment/flagparser"
)

// Do checks the passed flags for apply-max-expiry and then executes it.
//
// It only touches ExpireAt/UnlimitedTime (files) and Expiry (file requests) on the
// models.File/models.FileRequest values it reads back from GetAllMetadata/GetAllFileRequests,
// and saves each one back otherwise unchanged. That is what keeps this safe to run on a
// sealed instance, before the master key exists: NameEncryptedRaw/NoteEncryptedRaw, populated
// by every read, is carried straight back through SaveMetaData/SaveFileRequest, so an
// encrypted name whose plaintext cannot be read here is still written back byte for byte
// instead of being blanked out - the same guarantee database.Migrate relies on, and the same
// bug (blanking every stored name) that this must not reintroduce.
func Do(flags flagparser.ApplyMaxExpiryFlags) {
	// The database is deliberately left open on return: this command always runs as the last
	// thing before the process exits (see cmd/gokapi/Main.go's handleApplyMaxExpiry), the same
	// way a normal server boot never closes it until shutdown - there is no earlier point at
	// which closing it would matter, and doing so here would only get in the way of a caller
	// that wants to inspect the result afterwards (as the tests for this package do).
	configuration.Load()
	configuration.ConnectDatabase()

	maxExpiry := time.Duration(configuration.GetEnvironment().MaxExpiry)
	if maxExpiry <= 0 {
		fmt.Println("No maximum expiry is configured (GOKAPI_MAX_EXPIRY is unset or 0). Refusing to run - there is nothing to clamp to.")
		osExit(1)
		return
	}
	maxTimestamp := time.Now().Add(maxExpiry).Unix()

	filesChanged := applyFiles(maxTimestamp, flags.DryRun)
	requestsChanged := applyRequests(maxTimestamp, flags.DryRun)

	verb := "Clamped"
	if flags.DryRun {
		verb = "Dry run: would clamp"
	}
	fmt.Printf("%s %d file(s) and %d file request(s) to %s\n", verb, filesChanged, requestsChanged, time.Unix(maxTimestamp, 0).UTC())
}

// applyFiles clamps every file that is unlimited or expires after maxTimestamp. Files pending
// deletion are left alone: they match neither condition's intent, since they are already on
// their way out on their own schedule.
func applyFiles(maxTimestamp int64, dryRun bool) int {
	changed := 0
	for _, file := range database.GetAllMetadata() {
		if file.IsPendingForDeletion() {
			continue
		}
		if !file.UnlimitedTime && file.ExpireAt <= maxTimestamp {
			continue
		}
		fmt.Printf("file %s: expiry %s -> %s\n", file.Id, describeExpiry(file.UnlimitedTime, file.ExpireAt), time.Unix(maxTimestamp, 0).UTC())
		changed++
		if dryRun {
			continue
		}
		file.ExpireAt = maxTimestamp
		file.UnlimitedTime = false
		database.SaveMetaData(file)
	}
	return changed
}

// applyRequests clamps every file request that is unlimited (Expiry == 0, see
// models.FileRequest.IsUnlimitedTime) or expires after maxTimestamp.
func applyRequests(maxTimestamp int64, dryRun bool) int {
	changed := 0
	for _, request := range database.GetAllFileRequests() {
		unlimited := request.IsUnlimitedTime()
		if !unlimited && request.Expiry <= maxTimestamp {
			continue
		}
		fmt.Printf("file request %s: expiry %s -> %s\n", request.Id, describeExpiry(unlimited, request.Expiry), time.Unix(maxTimestamp, 0).UTC())
		changed++
		if dryRun {
			continue
		}
		request.Expiry = maxTimestamp
		database.SaveFileRequest(request)
	}
	return changed
}

func describeExpiry(unlimited bool, expireAt int64) string {
	if unlimited {
		return "unlimited"
	}
	return time.Unix(expireAt, 0).UTC().String()
}

// Declared for testing
var osExit = os.Exit
