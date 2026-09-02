package models

import (
	"testing"
	"time"

	"github.com/forceu/gokapi/internal/test"
)

func TestFileRequest_PopulateAndHelpers(t *testing.T) {
	now := time.Now().Unix()

	files := map[string]File{
		"file1": {
			Id:              "file1",
			UploadRequestId: "req1",
			SizeBytes:       1000,
			UploadDate:      now - 100,
		},
		"file2": {
			Id:              "file2",
			UploadRequestId: "req1",
			SizeBytes:       2000,
			UploadDate:      now,
		},
		"file3": {
			Id:              "file3",
			UploadRequestId: "other",
			SizeBytes:       9999,
			UploadDate:      now,
		},
	}

	fr := &FileRequest{
		Id:       "req1",
		MaxFiles: 5,
		MaxSize:  10,
	}

	fr.Populate(files, 8)
	test.IsEqualInt(t, fr.UploadedFiles, 2)
	test.IsEqualInt(t, fr.MaxFiles, 5)
	test.IsEqualInt(t, fr.CombinedMaxSize, 8)
	test.IsEqualInt(t, fr.FilesRemaining(), 3)

	test.IsEqualInt64(t, fr.TotalFileSize, int64(3000))
	test.IsEqualInt64(t, fr.LastUpload, now)
	test.IsEqualInt(t, len(fr.FileIdList), 2)

	test.IsNotEqualString(t, fr.GetReadableDateLastUpdate(), "None")
	test.IsNotEqualString(t, fr.GetFilesAsString(), "")

	fr = &FileRequest{
		Id:            "req2",
		UploadedFiles: 5,
		MaxFiles:      2,
		TotalFileSize: 102400,
	}
	test.IsEqualInt(t, fr.FilesRemaining(), 0)
	test.IsEqualString(t, fr.GetReadableDateLastUpdate(), "None")
	test.IsEqualString(t, fr.GetReadableTotalSize(), "100.0 kB")

}

func TestFileRequest_UnlimitedFlags(t *testing.T) {
	fr := &FileRequest{
		MaxFiles: 0,
		MaxSize:  0,
		Expiry:   0,
	}

	test.IsEqualBool(t, fr.IsUnlimitedFiles(), true)
	test.IsEqualBool(t, fr.IsUnlimitedSize(), true)
	test.IsEqualBool(t, fr.IsUnlimitedTime(), true)
	test.IsEqualBool(t, !fr.HasRestrictions(), true)
}

func TestFileRequest_IsExpired(t *testing.T) {
	fr := &FileRequest{
		Expiry: time.Now().Unix() - 10,
	}

	test.IsEqualBool(t, fr.IsExpired(), true)
}

func TestFileRequest_CollaboratorsEncodeDecode(t *testing.T) {
	// Empty string is what a Redis hash written before the field existed reads as, and what a
	// sqlite/postgres row can never hold (default '[]') - both must mean "nobody".
	ids, err := DecodeCollaborators("")
	test.IsNil(t, err)
	test.IsEqualInt(t, len(ids), 0)

	ids, err = DecodeCollaborators("[]")
	test.IsNil(t, err)
	test.IsEqualInt(t, len(ids), 0)

	// Sorted and de-duplicated on the way in, and ids that cannot be a user are dropped.
	ids, err = DecodeCollaborators("[7,3,7,0,-1]")
	test.IsNil(t, err)
	test.IsEqual(t, ids, []int{3, 7})

	_, err = DecodeCollaborators("not json")
	test.IsEqualBool(t, err != nil, true)

	test.IsEqualString(t, EncodeCollaborators(nil), "[]")
	test.IsEqualString(t, EncodeCollaborators([]int{9, 2, 9}), "[2,9]")
}

func TestFileRequest_CollaboratorMembership(t *testing.T) {
	fr := FileRequest{Id: "req1", UserId: 1}
	test.IsEqualBool(t, fr.IsCollaborator(2), false)
	test.IsEqualInt(t, len(fr.CollaboratorIds()), 0)

	fr.SetCollaboratorIds([]int{5, 2})
	test.IsEqual(t, fr.CollaboratorIds(), []int{2, 5})
	test.IsEqualString(t, fr.CollaboratorsRaw, "[2,5]")
	test.IsEqualBool(t, fr.IsCollaborator(5), true)
	test.IsEqualBool(t, fr.IsCollaborator(1), false)
	// Names are display-only and never come from SetCollaboratorIds.
	test.IsEqualString(t, fr.Collaborators[0].Name, "")

	fr.SetCollaboratorIds(nil)
	test.IsEqualInt(t, len(fr.Collaborators), 0)
	test.IsEqualString(t, fr.CollaboratorsRaw, "[]")
}
