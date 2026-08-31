package redis

import (
	"bytes"
	"encoding/gob"
	"strings"

	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
	redigo "github.com/gomodule/redigo/redis"
)

const (
	prefixMetaData = "fmeta:"
)

// GetAllMetadata returns a map of all available files
func (p DatabaseProvider) GetAllMetadata() map[string]models.File {
	result := make(map[string]models.File)
	maps := p.getAllHashesWithPrefix(prefixMetaData)
	for k, v := range maps {
		file, err := dbToMetadata(k, v)
		helper.Check(err)
		result[file.Id] = file
	}
	return result
}

func dbToMetadata(id string, input []any) (models.File, error) {
	var result models.File
	err := redigo.ScanStruct(input, &result)
	if err != nil {
		return models.File{}, err
	}
	result.Id = strings.Replace(id, prefixMetaData, "", 1)
	// redigo has no concept of a NULL hash field: a file that never had a share password
	// still round-trips EncryptedSharePassword as an empty, non-nil []byte rather than nil (an
	// absent hash field scans to the zero value, and []byte's zero value is non-nil-empty once
	// ScanStruct has touched it). Normalised to nil so callers (and equality checks) see the
	// same "nothing stored" value the sqlite/postgres providers already return for a NULL
	// column.
	if len(result.EncryptedSharePassword) == 0 {
		result.EncryptedSharePassword = nil
	}
	return unmarshalEncryptionInfo(result)
}

func marshalEncryptionInfo(f models.File) (models.File, error) {
	var encInfo bytes.Buffer
	enc := gob.NewEncoder(&encInfo)
	err := enc.Encode(f.Encryption)
	if err != nil {
		return f, err
	}
	f.InternalRedisEncryption = encInfo.Bytes()
	return f, nil
}

func unmarshalEncryptionInfo(f models.File) (models.File, error) {
	if f.InternalRedisEncryption == nil {
		f.Encryption = models.EncryptionInfo{}
		return f, nil
	}
	var result models.EncryptionInfo
	buf := bytes.NewBuffer(f.InternalRedisEncryption)
	dec := gob.NewDecoder(buf)
	err := dec.Decode(&result)
	if err != nil {
		return f, err
	}
	f.Encryption = result
	f.InternalRedisEncryption = nil
	return f, nil
}

// GetMetaDataById returns a models.File from the ID passed or false if the id is not valid
func (p DatabaseProvider) GetMetaDataById(id string) (models.File, bool) {
	result, ok := p.getHashMap(prefixMetaData + id)
	if !ok {
		return models.File{}, false
	}
	file, err := dbToMetadata(id, result)
	helper.Check(err)
	return file, true
}

// SaveMetaData stores the metadata of a file to the disk
func (p DatabaseProvider) SaveMetaData(file models.File) {
	marshalledFile, err := marshalEncryptionInfo(file)
	helper.Check(err)
	p.setHashMap(p.buildArgs(prefixMetaData + file.Id).AddFlat(marshalledFile))
}

// DeleteMetaData deletes information about a file
func (p DatabaseProvider) DeleteMetaData(id string) {
	p.deleteKey(prefixMetaData + id)
}

// IncreaseDownloadCount atomically increases the download count of a file. If decreaseRemainingDownloads
// is true, DownloadsRemaining is only decremented if it is currently greater than 0, via a Lua script that
// Redis runs as a single atomic operation, so the database itself refuses to go below zero; the return
// value reports whether this call actually consumed a remaining download. A false return means
// DownloadsRemaining was already 0 and the caller must not serve the file.
func (p DatabaseProvider) IncreaseDownloadCount(id string, decreaseRemainingDownloads bool) bool {
	if decreaseRemainingDownloads {
		return p.decrementHashFieldIfPositive(prefixMetaData+id, "DownloadsRemaining", "DownloadCount")
	}
	p.increaseHashmapIntField(prefixMetaData+id, "DownloadCount")
	return true
}

// GetDownloadsRemaining returns the remaining downloads of a file that does not implement UnlimitedDownloads
func (p DatabaseProvider) GetDownloadsRemaining(id string) int {
	file, ok := p.GetMetaDataById(id)
	if !ok {
		return 0
	}
	return file.DownloadsRemaining
}
