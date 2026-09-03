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

// Delete disposes of every file in a bundle and marks the bundle itself as deleted.
//
// The bundle row is deliberately not removed here. Its members keep their rows for the metadata
// retention period, so their owner still sees what was deleted, and those rows need the folder to
// still be there to be grouped under - removing it left the file list rendering them flat, with
// no folder at all. When the row goes is decided in one place, storage.CleanUp's
// cleanInvalidBundles, once no file row names the bundle any more; deciding it here would mean
// deciding against a sweep that runs in the background, and the answer would depend on which of
// the two got there first.
//
// The retained row carries no credential material, the same rule storage.disposeFile applies to a
// retained file record: the folder's own password, its stored share key and every recipient login
// token issued against it go now, not when the row is finally collected. Marked before the
// members are disposed of, so that no sweep can see the folder emptied while it still reads as
// live.
func Delete(bundle models.FileBundle) {
	storage.RevokeShareTokens(models.ShareResourceBundle, bundle.Id)
	bundle.PasswordHash = ""
	bundle.EncryptedSharePassword = nil
	bundle.DeletedAt = time.Now().Unix()
	database.SaveFileBundle(bundle)

	files := GetFiles(bundle)
	storage.DeleteFiles(files, true)
}
