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

// Delete deletes a bundle and all its associated files
func Delete(bundle models.FileBundle) {
	files := GetFiles(bundle)
	storage.DeleteFiles(files, true)
	database.DeleteFileBundle(bundle)
}
