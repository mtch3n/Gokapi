package filerequest

import (
	"time"

	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/storage"
)

// New creates a new file request object. It is not stored yet,
// and an API key has to be generated manually
func New(user models.User) models.FileRequest {
	return models.FileRequest{
		Id:               helper.GenerateRandomString(configuration.GetEnvironment().LengthId),
		UserId:           user.Id,
		CreationDate:     time.Now().Unix(),
		Name:             "Unnamed file request",
		Collaborators:    []models.FileRequestCollaborator{},
		CollaboratorsRaw: "[]",
	}
}

// Get returns a file request object by its ID and populates it
func Get(id string) (models.FileRequest, bool) {
	result, ok := database.GetFileRequest(id)
	if !ok {
		return models.FileRequest{}, false
	}
	result.Populate(database.GetAllMetadata(), configuration.Get().MaxFileSizeMB)
	return result, true
}

// GetAll returns a list of all file requests and populates them
func GetAll() []models.FileRequest {
	result := database.GetAllFileRequests()
	if len(result) == 0 {
		return result
	}
	allFiles := database.GetAllMetadata()
	maxServerSize := configuration.Get().MaxFileSizeMB
	for i, request := range result {
		request.Populate(allFiles, maxServerSize)
		result[i] = request
	}
	return result
}

// Delete all files associated with a file request and the request itself. The cascade itself
// lives in storage.DeleteFileRequest - see that function's comment for why.
func Delete(request models.FileRequest) {
	storage.DeleteFileRequest(request)
}
