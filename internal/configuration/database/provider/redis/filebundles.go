package redis

import (
	"cmp"
	"slices"

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
	slices.SortFunc(bundles, func(a, b models.FileBundle) int {
		return cmp.Or(
			cmp.Compare(b.CreationDate, a.CreationDate),
			cmp.Compare(a.Name, b.Name),
		)
	})
	return bundles
}

// SaveFileBundle stores the file bundle in the database
func (p DatabaseProvider) SaveFileBundle(bundle models.FileBundle) {
	p.setHashMap(p.buildArgs(prefixFileBundles + bundle.Id).AddFlat(bundle))
}

// DeleteFileBundle deletes a file bundle with the given ID
func (p DatabaseProvider) DeleteFileBundle(bundle models.FileBundle) {
	p.deleteKey(prefixFileBundles + bundle.Id)
}
