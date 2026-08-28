package models

import (
	"time"
)

// FileBundle contains information about a file bundle (folder)
type FileBundle struct {
	Id           string `json:"id" redis:"id"`                   // The internal ID of the bundle
	Name         string `json:"name" redis:"name"`               // The name of the bundle
	UserId       int    `json:"userid" redis:"userid"`           // The user ID of the owner
	CreationDate int64  `json:"creationdate" redis:"creationdate"` // The timestamp of the bundle creation
}

// Populate scans all files and returns those belonging to this bundle
func (b *FileBundle) Populate(files map[string]File) ([]File, int64, int) {
	var memberFiles []File
	var totalSize int64
	count := 0

	for _, file := range files {
		if file.BundleId == b.Id && !file.IsPendingForDeletion() {
			memberFiles = append(memberFiles, file)
			totalSize += file.SizeBytes
			count++
		}
	}

	return memberFiles, totalSize, count
}

// IsExpired returns true if the bundle was created more than 24 hours ago
func (b *FileBundle) IsExpired() bool {
	return time.Now().Unix() > b.CreationDate+86400
}
