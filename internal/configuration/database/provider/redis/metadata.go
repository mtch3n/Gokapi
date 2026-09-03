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
	// NameEncryptedRaw is deliberately left populated here (not nilled out after decrypting into
	// Name) so a caller that re-saves this File unchanged - see encryptNameForSave and
	// models.File.NameEncryptedRaw - can write the original bytes back verbatim rather than
	// re-deriving them, which matters most for database.Migrate: it runs before the master key is
	// loaded, so it can never decrypt an encrypted name into Name in the first place.
	result.Name = encryption.DecryptFileName(result.NameEncryptedRaw)
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
	file.NameEncryptedRaw = encryptedName
	marshalledFile, err := marshalEncryptionInfo(file)
	helper.Check(err)
	p.setHashMap(p.buildArgs(prefixMetaData + file.Id).AddFlat(marshalledFile))
}

// encryptNameForSave returns the value to store in the NameEncrypted hash field for this file. An
// empty name is never a real one - uploads always set one - so it means this models.File was read
// back while the instance was still sealed, when encryption.DecryptFileName had no key and
// reported the name as empty. Re-encrypting that would overwrite the stored name with nothing,
// which matters because bookkeeping writes that are allowed while sealed (marking a file pending
// deletion, clearing a hotlink) go through this same path.
//
// NameEncryptedRaw, if the caller's File model was itself the result of a read, carries the exact
// bytes that were stored for this row (see models.File.NameEncryptedRaw) and is used verbatim -
// this is what makes database.Migrate safe: it runs before the master key is loaded, so it can
// never decrypt an encrypted name into file.Name, but it must still copy the original ciphertext
// rather than lose it. Looking it up in this database is only a fallback for a File model that was
// never read (so carries no raw bytes), kept for the in-place bookkeeping writes this always
// handled correctly before NameEncryptedRaw existed.
func (p DatabaseProvider) encryptNameForSave(file models.File) ([]byte, error) {
	if file.Name != "" {
		return encryption.EncryptFileName(file.Name)
	}
	if file.NameEncryptedRaw != nil {
		return file.NameEncryptedRaw, nil
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

// AcquireDownload atomically lets one request through to a capped file's content, via the Lua
// script in acquireWindowedDownload - see that function for the window rule and for why Redis
// needs no equivalent of the SQL providers' lost-race retry.
func (p DatabaseProvider) AcquireDownload(id string, timeNow, leeway int64) (bool, bool) {
	result := p.acquireWindowedDownload(prefixMetaData+id, "WindowOpenedAt", "DownloadsRemaining", "DownloadCount",
		timeNow, timeNow-leeway)
	return result > 0, result == 2
}

// IncreaseDownloadCount atomically increases the download count of a file, leaving its allowance
// and its window untouched. Only for a file with UnlimitedDownloads set.
func (p DatabaseProvider) IncreaseDownloadCount(id string) {
	p.increaseHashmapIntField(prefixMetaData+id, "DownloadCount")
}

// MigratePlaintextFileNames re-encrypts every file name, folder name, request name and request
// note still stored in a plaintext hash field, across the fmeta:, fbn: and frq: prefixes, and
// removes each field once converted. Returns the total number of values migrated across all
// three - see LogFileNameMigration, which reports this as one count. It is a separate step rather
// than part of Upgrade because encrypting needs the master key, which an Input-level instance does
// not have until an administrator unseals it - long after Upgrade has run at boot.
//
// Unlike the SQL providers this is not driven by the scheme version, because Redis has no schema
// to version: a hash written before a value was encrypted is distinguishable from a current one by
// carrying its plaintext field at all, which is the condition used here. Doing nothing and
// reporting 0 once no hash has one is the normal steady state, so this is safe to call on every
// unseal, and an interrupted run resumes on the next call.
func (p DatabaseProvider) MigratePlaintextFileNames() int {
	migrated := p.migrateFileMetaDataNames()
	migrated += p.migrateFileBundleNames()
	migrated += p.migrateFileRequestNamesAndNotes()
	return migrated
}

// migrateFileMetaDataNames is MigratePlaintextFileNames' original, file-specific body - see that
// function's comment for the full reasoning.
func (p DatabaseProvider) migrateFileMetaDataNames() int {
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
