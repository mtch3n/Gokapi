package filebundle

import (
	"time"

	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/storage"
)

// Create creates a new file bundle. It starts open - unprotected, no expiry, no download limit -
// the same default a caller gets by leaving every optional setting off models.UploadParameters
// for a plain file. apiFolderCreate applies any explicit password/expiry/downloads on top of this
// once the bundle exists.
func Create(name string, userId int) models.FileBundle {
	bundle := models.FileBundle{
		Id:                 helper.GenerateRandomString(configuration.GetEnvironment().LengthId),
		Name:               name,
		UserId:             userId,
		CreationDate:       time.Now().Unix(),
		UnlimitedTime:      true,
		UnlimitedDownloads: true,
	}
	database.SaveFileBundle(bundle)
	return bundle
}

// Get returns a file bundle object by its ID
func Get(id string) (models.FileBundle, bool) {
	return database.GetFileBundle(id)
}

// GetAll returns a list of all file bundles
func GetAll() []models.FileBundle {
	return database.GetAllFileBundles()
}

// GetFiles returns all files associated with a bundle
func GetFiles(bundle models.FileBundle) []models.File {
	var result []models.File
	files := database.GetAllMetadata()
	for _, file := range files {
		if file.BundleId == bundle.Id {
			result = append(result, file)
		}
	}
	return result
}

// Delete deletes a bundle and all its associated files.
//
// The bundle row itself is only removed when nothing refers to it any more. A disposed file
// keeps its row for the metadata retention period so its owner can still see what was deleted,
// and the folder has to outlive those rows: deleting it straight away left every member
// pointing at a bundle that no longer existed, so the file list had nothing to group them
// under and showed them flat, which is what the retention period exists to avoid. Once the
// last member row is purged, storage.CleanUp's cleanInvalidBundles collects the bundle - the
// same rule, in the same one place, for both paths. A folder that really had nothing left to
// keep is still removed here rather than waiting for that sweep.
func Delete(bundle models.FileBundle) {
	files := GetFiles(bundle)
	storage.DeleteFiles(files, true)
	if !hasStoredMember(bundle.Id) {
		database.DeleteFileBundle(bundle)
	}
}

// hasStoredMember reports whether any file ROW still names this bundle, disposed or not.
// Deliberately not models.File.IsBundleMember, which answers the different question of what a
// recipient may be served: every member has just been disposed of, so that would always say no.
func hasStoredMember(bundleId string) bool {
	for _, file := range database.GetAllMetadata() {
		if file.BundleId == bundleId {
			return true
		}
	}
	return false
}
