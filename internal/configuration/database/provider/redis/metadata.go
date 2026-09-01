package redis

import (
	"bytes"
	"encoding/gob"
	"strings"

	"github.com/forceu/gokapi/internal/encryption"
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
	result.Name = encryption.DecryptFileName(result.InternalRedisName)
	result.InternalRedisName = nil
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
	encryptedName, err := p.encryptNameForSave(file)
	helper.Check(err)
	file.InternalRedisName = encryptedName
	marshalledFile, err := marshalEncryptionInfo(file)
	helper.Check(err)
	p.setHashMap(p.buildArgs(prefixMetaData + file.Id).AddFlat(marshalledFile))
}

// encryptNameForSave returns the value to store in the NameEncrypted hash field for this file. An
// empty name is never a real one - uploads always set one - so it means this models.File was read
// back while the instance was still sealed, when encryption.DecryptFileName had no key and
// reported the name as empty. Re-encrypting that would overwrite the stored name with nothing,
// which matters because bookkeeping writes that are allowed while sealed (marking a file pending
// deletion, clearing a hotlink) go through this same path. Keeping whatever is already stored is
// the only correct answer, and on a fresh insert there is nothing to keep.
func (p DatabaseProvider) encryptNameForSave(file models.File) ([]byte, error) {
	if file.Name != "" {
		return encryption.EncryptFileName(file.Name)
	}
	hash, ok := p.getHashMap(prefixMetaData + file.Id)
	if !ok {
		return nil, nil
	}
	storedName, ok := hashFieldString(hash, "NameEncrypted")
	if !ok {
		return nil, nil
	}
	return []byte(storedName), nil
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

// MigratePlaintextFileNames re-encrypts every file name still stored in the plaintext Name hash
// field and then removes that field, reporting how many files it converted. It is a separate step
// rather than part of Upgrade because encrypting needs the master key, which an Input-level
// instance does not have until an administrator unseals it - long after Upgrade has run at boot.
//
// Unlike the SQL providers this is not driven by the scheme version, because Redis has no schema
// to version: a hash written before file names were encrypted is distinguishable from a current
// one by carrying a Name field at all, which is the condition used here. Doing nothing and
// reporting 0 once no hash has one is the normal steady state, so this is safe to call on every
// unseal, and an interrupted run resumes on the next call.
func (p DatabaseProvider) MigratePlaintextFileNames() int {
	migrated := 0
	for key, hash := range p.getAllHashesWithPrefix(prefixMetaData) {
		plaintextName, ok := hashFieldString(hash, "Name")
		if !ok {
			continue
		}
		encryptedName, err := encryption.EncryptFileName(plaintextName)
		helper.Check(err)
		p.setHashMap(p.buildArgs(key).Add("NameEncrypted").Add(encryptedName))
		p.deleteHashField(key, "Name")
		migrated++
	}
	return migrated
}

// hashFieldString reads one field out of the flat field/value list an HGETALL returns. Only used
// by the migration above: everything else scans the whole hash into models.File in one go.
func hashFieldString(hash []any, field string) (string, bool) {
	for i := 0; i+1 < len(hash); i += 2 {
		name, err := redigo.String(hash[i], nil)
		if err != nil || name != field {
			continue
		}
		value, err := redigo.String(hash[i+1], nil)
		if err != nil {
			return "", false
		}
		return value, true
	}
	return "", false
}
