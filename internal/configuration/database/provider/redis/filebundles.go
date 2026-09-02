package redis

import (
	"cmp"
	"slices"

	"github.com/forceu/gokapi/internal/encryption"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/models"
	redigo "github.com/gomodule/redigo/redis"
)

const (
	prefixFileBundles = "fbn:"
)

func dbToFileBundle(input []any) (models.FileBundle, error) {
	var result models.FileBundle
	err := redigo.ScanStruct(input, &result)
	if err != nil {
		return models.FileBundle{}, err
	}
	// See the identical normalisation in metadata.go's dbToMetadata: redigo scans an absent
	// hash field to an empty, non-nil []byte rather than nil.
	if len(result.EncryptedSharePassword) == 0 {
		result.EncryptedSharePassword = nil
	}
	// NameEncryptedRaw is deliberately left populated here (not nilled out after decrypting into
	// Name) so a caller that re-saves this FileBundle unchanged can write the original bytes back
	// verbatim rather than re-deriving them - see encryptBundleNameForSave and
	// models.FileBundle.NameEncryptedRaw.
	result.Name = encryption.DecryptFileName(result.NameEncryptedRaw)
	return result, nil
}

// GetFileBundle returns the FileBundle or false if not found
func (p DatabaseProvider) GetFileBundle(id string) (models.FileBundle, bool) {
	if id == "" {
		return models.FileBundle{}, false
	}
	result, ok := p.getHashMap(prefixFileBundles + id)
	if !ok {
		return models.FileBundle{}, false
	}
	bundle, err := dbToFileBundle(result)
	helper.Check(err)
	return bundle, true
}

// GetAllFileBundles returns an array with all file bundles, ordered by creation date
func (p DatabaseProvider) GetAllFileBundles() []models.FileBundle {
	result := make([]models.FileBundle, 0)
	maps := p.getAllHashesWithPrefix(prefixFileBundles)
	for _, v := range maps {
		bundle, err := dbToFileBundle(v)
		helper.Check(err)
		result = append(result, bundle)
	}
	return sortFileBundles(result)
}

func sortFileBundles(bundles []models.FileBundle) []models.FileBundle {
	// Tie-broken on Id rather than Name: Name is now ciphertext, and ordering by it would be
	// meaningless.
	slices.SortFunc(bundles, func(a, b models.FileBundle) int {
		return cmp.Or(
			cmp.Compare(b.CreationDate, a.CreationDate),
			cmp.Compare(a.Id, b.Id),
		)
	})
	return bundles
}

// SaveFileBundle stores the file bundle in the database
func (p DatabaseProvider) SaveFileBundle(bundle models.FileBundle) {
	encryptedName, err := p.encryptBundleNameForSave(bundle)
	helper.Check(err)
	bundle.NameEncryptedRaw = encryptedName
	p.setHashMap(p.buildArgs(prefixFileBundles + bundle.Id).AddFlat(bundle))
}

// encryptBundleNameForSave returns the value to store in the NameEncrypted hash field for this
// bundle. Mirrors metadata.go's encryptNameForSave exactly - see that comment for the full
// reasoning. An empty name is never a real one - Create always sets one - so it means this
// models.FileBundle was read back while the instance was still sealed.
func (p DatabaseProvider) encryptBundleNameForSave(bundle models.FileBundle) ([]byte, error) {
	if bundle.Name != "" {
		return encryption.EncryptFileName(bundle.Name)
	}
	if bundle.NameEncryptedRaw != nil {
		return bundle.NameEncryptedRaw, nil
	}
	hash, ok := p.getHashMap(prefixFileBundles + bundle.Id)
	if !ok {
		return nil, nil
	}
	storedName, ok := hashFieldString(hash, "NameEncrypted")
	if !ok {
		return nil, nil
	}
	return []byte(storedName), nil
}

// DeleteFileBundle deletes a file bundle with the given ID
func (p DatabaseProvider) DeleteFileBundle(bundle models.FileBundle) {
	p.deleteKey(prefixFileBundles + bundle.Id)
}

// migrateFileBundleNames re-encrypts every bundle name still stored in the plaintext name hash
// field and then removes that field, reporting how many bundles it converted. Same shape as
// metadata.go's migrateFileMetaDataNames.
func (p DatabaseProvider) migrateFileBundleNames() int {
	migrated := 0
	for key, hash := range p.getAllHashesWithPrefix(prefixFileBundles) {
		plaintextName, ok := hashFieldString(hash, "name")
		if !ok {
			continue
		}
		encryptedName, err := encryption.EncryptFileName(plaintextName)
		helper.Check(err)
		p.setHashMap(p.buildArgs(key).Add("NameEncrypted").Add(encryptedName))
		p.deleteHashField(key, "name")
		migrated++
	}
	return migrated
}
