package models

import (
	"encoding/json"
)

// Configuration is a struct that contains the global configuration
type Configuration struct {
	Authentication      AuthenticationConfig `json:"Authentication"`
	Port                string               `json:"Port"`
	ServerUrl           string               `json:"ServerUrl"`
	RedirectUrl         string               `json:"RedirectUrl"`
	PublicName          string               `json:"PublicName"`
	DataDir             string               `json:"DataDir"`
	DatabaseUrl         string               `json:"DatabaseUrl"`
	ConfigVersion       int                  `json:"ConfigVersion"`
	MaxFileSizeMB       int                  `json:"MaxFileSizeMB"`
	MaxMemory           int                  `json:"MaxMemory"`
	ChunkSize           int                  `json:"ChunkSize"`
	MaxParallelUploads  int                  `json:"MaxParallelUploads"`
	Encryption          Encryption           `json:"Encryption"`
	UseSsl              bool                 `json:"UseSsl"`
	PicturesAlwaysLocal bool                 `json:"PicturesAlwaysLocal"`
	SaveIp              bool                 `json:"SaveIp"`
	IncludeFilename     bool                 `json:"IncludeFilename"`
	// StoreShareKeys, when true, opts the server into keeping an encrypted copy of a share
	// password - typed or auto-generated alike - so an authorised caller can retrieve it later (see
	// /api/files/{id}/sharekey). Defaults to false: without this flag, no plaintext or
	// encrypted password is ever persisted beyond the PasswordHash used to verify it.
	StoreShareKeys bool `json:"StoreShareKeys"`
	// DownloadSessionKey is the MAC key for the download session tokens that let the party who
	// spent a download keep retrying it while its window is open (see downloadsession.Sign).
	// Generated on first start and never rotated automatically: deleting it from the config
	// invalidates every token in flight, which costs at most one leeway window of retries.
	//
	// Kept here rather than derived from the master key because it must work at every encryption
	// level, including a sealed Level 4 boot and a Level 0 test instance, where no master key
	// exists to derive from.
	DownloadSessionKey string `json:"DownloadSessionKey"`
}

// Encryption holds information about the encryption used on this file
type Encryption struct {
	Level        int
	Cipher       []byte
	Salt         string
	Checksum     string
	ChecksumSalt string
}

// ToJson returns an indented Json representation
func (c Configuration) ToJson() []byte {
	result, err := json.MarshalIndent(c, "", "  ")
	checkError(err)
	return result
}

// ToString returns the object as an unindented JSON string used for test units
func (c Configuration) ToString() string {
	result, err := json.Marshal(c)
	checkError(err)
	return string(result)
}

func checkError(err error) {
	if err != nil {
		panic(err)
	}
}
