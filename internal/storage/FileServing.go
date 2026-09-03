package storage

/**
Serving and processing uploaded files
*/

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/encryption"
	"github.com/forceu/gokapi/internal/environment"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/logging"
	"github.com/forceu/gokapi/internal/logging/serverstats"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/storage/chunking"
	"github.com/forceu/gokapi/internal/storage/filesystem"
	"github.com/forceu/gokapi/internal/storage/filesystem/s3filesystem/aws"
	"github.com/forceu/gokapi/internal/storage/processingstatus"
	"github.com/forceu/gokapi/internal/webserver/api/mutex/apimutex"
	"github.com/forceu/gokapi/internal/webserver/downloadstatus"
	"github.com/forceu/gokapi/internal/webserver/headers"
	"github.com/forceu/gokapi/internal/webserver/sse"
	"github.com/jinzhu/copier"
)

// ErrorFileTooLarge is an error which is raised when a file larger than the set maximum is uploaded
var ErrorFileTooLarge = errors.New("upload limit exceeded")

// ErrorChunkTooSmall is an error which is raised when a chunk is smaller than 5MB
var ErrorChunkTooSmall = errors.New("chunk is too small")

// ErrorReplaceE2EFile is caused when an end-to-end encrypted file is replaced
var ErrorReplaceE2EFile = errors.New("end-to-end encrypted files cannot be replaced")

// ErrorFileNotFound is raised when an invalid ID is passed or the file has expired
var ErrorFileNotFound = errors.New("file not found")

// ErrorInvalidPresign is raised when an invalid presign key has been passed or it has expired
var ErrorInvalidPresign = errors.New("invalid presign")

// ErrorInstanceSealed is returned by NewFile and NewFileFromChunk when the configured encryption
// level requires the master key (see isEncryptionRequested) and the instance has not yet been
// unsealed with the correct password (see encryption.IsSealed). Checked before either function
// does any work, so a sealed instance refuses an upload cleanly instead of failing deep inside
// generateHashAndEncrypt/encryptChunkFile, which call helper.Check on the encryption error and
// would otherwise panic the request.
var ErrorInstanceSealed = errors.New("instance is sealed")

// NewFile creates a new file in the system. Called after an upload from the API has been completed. If a file with the same sha1 hash
// already exists, it is deduplicated. This function gathers information about the file, creates an ID and saves
// it into the global configuration. It is now only used by the API, the web UI uses NewFileFromChunk
func NewFile(fileContent io.Reader, fileHeader *multipart.FileHeader, userId int, uploadRequest models.UploadParameters) (models.File, error) {
	if isEncryptionRequested() && encryption.IsSealed() {
		return models.File{}, ErrorInstanceSealed
	}
	if !isAllowedFileSize(fileHeader.Size) {
		return models.File{}, ErrorFileTooLarge
	}
	var hasBeenRenamed bool
	reader, id, tempFile, encInfo := generateHashAndEncrypt(fileContent, fileHeader)
	defer deleteTempFile(tempFile, &hasBeenRenamed)
	header, err := chunking.ParseMultipartHeader(fileHeader)
	if err != nil {
		return models.File{}, err
	}
	file := createNewMetaData(id, header, userId, uploadRequest)
	file.Encryption = encInfo
	filename := configuration.Get().DataDir + "/" + file.SHA1
	dataDir := configuration.Get().DataDir

	// Encrypted uploads are given a fresh, random storage identifier by generateHashAndEncrypt
	// and must never be deduplicated (each gets its own blob and its own key), so an existing
	// blob is only ever reused for unencrypted uploads.
	fileWithHashExists := !file.Encryption.IsEncrypted && FileExists(file, configuration.Get().DataDir)

	if !file.IsLocalStorage() {
		if !fileWithHashExists {
			_, err = aws.Upload(reader, file)
			if err != nil {
				return models.File{}, err
			}
		}
		database.SaveMetaData(file)
		return file, nil
	}

	if !fileWithHashExists {
		if tempFile != nil {
			err = tempFile.Close()
			helper.Check(err)
			err = os.Rename(tempFile.Name(), dataDir+"/"+file.SHA1)
			helper.Check(err)
			hasBeenRenamed = true
			database.SaveMetaData(file)
			return file, nil
		}
		destinationFile, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return models.File{}, err
		}
		defer destinationFile.Close()
		_, err = io.Copy(destinationFile, reader)
		if err != nil {
			return models.File{}, err
		}
	}
	database.SaveMetaData(file)
	return file, nil
}

// isAllowedFileSize returns true if the file is not greater than the allowed filesize
func isAllowedFileSize(size int64) bool {
	return size <= int64(configuration.Get().MaxFileSizeMB)*1024*1024
}

// validateChunkInfo checks if the filesize is allowed and if the submitted filesize (user input) is the actual filesize
func validateChunkInfo(file *os.File, fileHeader chunking.FileHeader) error {
	if !isAllowedFileSize(fileHeader.Size) {
		return ErrorFileTooLarge
	}
	size, err := helper.GetFileSize(file)
	if err != nil {
		return err
	}
	if size != fileHeader.Size {
		return errors.New("total filesize does not match")
	}
	return nil
}

// GetUploadCounts returns the currently uploaded files per user
func GetUploadCounts() map[int]int {
	result := make(map[int]int)
	timeNow := time.Now().Unix()
	files := database.GetAllMetadata()
	resolver := NewDownloadAccessResolver()
	for _, file := range files {
		access := resolver.Of(file)
		if !access.IsExpired(timeNow) && !access.IsExhausted(timeNow) {
			result[file.UserId] = result[file.UserId] + 1
		}
	}
	return result
}

// NewFileFromChunk creates a new file in the system after a chunk upload has fully completed. If a file with the same sha1 hash
// already exists, it is deduplicated. This function gathers information about the file, creates an ID and saves
// it into the global configuration.
//
// Serialised end-to-end on chunkId via apimutex: without this, N parallel completion
// requests for the exact same chunk id all pass chunking.GetFileByChunkId successfully - the
// chunk file backing chunkId is only removed near the very end of this function, by
// encryptChunkFile or the MoveToFilesystem call below - so every one of them would redundantly
// hash and, if encryption is active, fully encrypt the same content before racing to move/remove
// the same source file. That is both an anonymous disk/CPU exhaustion vector (each loser still did
// a full encryption pass before losing) and, without encryptChunkFile's own fix, a way to leak the
// loser's encrypted temp file. Holding the lock for the whole function - not just the final
// move/remove - is what makes this idempotent: a second call for the same chunkId that arrives
// after the first has finished simply finds the chunk file gone and fails cleanly via
// chunking.GetFileByChunkId, having done no hashing or encryption work at all.
func NewFileFromChunk(chunkId string, fileHeader chunking.FileHeader, userId int, uploadRequest models.UploadParameters) (models.File, error) {
	if isEncryptionRequested() && encryption.IsSealed() {
		return models.File{}, ErrorInstanceSealed
	}
	apimutex.Lock(apimutex.TypeMetaData, chunkId)
	defer apimutex.Unlock(apimutex.TypeMetaData, chunkId)

	file, err := chunking.GetFileByChunkId(chunkId)
	if err != nil {
		return models.File{}, err
	}
	defer file.Close()
	err = validateChunkInfo(file, fileHeader)
	if err != nil {
		_ = chunking.DeleteChunk(chunkId)
		return models.File{}, err
	}

	processingstatus.Set(chunkId, processingstatus.StatusHashingOrEncrypting, models.File{}, userId, nil)
	hash, err := getChunkFileHash(file, uploadRequest.IsEndToEndEncrypted)
	if err != nil {
		return models.File{}, err
	}
	metaData := createNewMetaData(hash, fileHeader, userId, uploadRequest)
	// Encrypted uploads (including end-to-end encrypted ones) are given a fresh, random storage
	// identifier by getChunkFileHash and must never be deduplicated, so an existing blob is only
	// ever reused for unencrypted uploads.
	fileExists := !metaData.Encryption.IsEncrypted && FileExists(metaData, configuration.Get().DataDir)
	if fileExists {
		err = file.Close()
		if err != nil {
			return models.File{}, err
		}
		err = os.Remove(file.Name())
		if err != nil {
			return models.File{}, err
		}
	}

	if !fileExists {
		fileToMove := file
		if !isEncryptionRequested() {
			_, err = file.Seek(0, io.SeekStart)
			if err != nil {
				return models.File{}, err
			}
		} else {
			tempFile, err := encryptChunkFile(file, &metaData)
			if err != nil {
				return models.File{}, err
			}
			fileToMove = tempFile
		}
		processingstatus.Set(chunkId, processingstatus.StatusUploading, models.File{}, userId, nil)
		if metaData.IsLocalStorage() {
			err = filesystem.GetLocal().MoveToFilesystem(fileToMove, metaData)
		} else {
			err = filesystem.ActiveStorageSystem.MoveToFilesystem(fileToMove, metaData)
		}
		if err != nil {
			return models.File{}, err
		}
	}
	database.SaveMetaData(metaData)
	processingstatus.Set(chunkId, processingstatus.StatusFinished, metaData, userId, nil)
	return metaData, nil
}

// getChunkFileHash returns the storage identifier for a completed chunk upload. Files that are
// encrypted, whether end-to-end or server-side, must never be deduplicated (see NewFileFromChunk),
// so they are given a random identifier instead of one derived from their content. Only a plain,
// unencrypted upload is identified by its content hash, which allows it to be deduplicated.
func getChunkFileHash(file *os.File, isEndToEndEncryted bool) (string, error) {
	if isEndToEndEncryted {
		return "e2e-" + helper.GenerateRandomString(20), nil
	}
	if isEncryptionRequested() {
		return newEncryptedFileId(), nil
	}
	hash, err := hashFile(file, false)
	if err != nil {
		_ = file.Close()
		return "", err
	}
	return hash, nil
}

// newEncryptedFileId returns a random storage identifier for a file that is encrypted server-side,
// following the same pattern getChunkFileHash already uses for end-to-end encrypted uploads
// ("e2e-" + random). It is content-independent so that two uploads with colliding SHA-1 hashes
// never end up sharing, or overwriting, the same on-disk blob.
func newEncryptedFileId() string {
	return "enc-" + helper.GenerateRandomString(20)
}

func encryptChunkFile(file *os.File, metadata *models.File) (*os.File, error) {

	var removePlainTextTemp = func() {
		err := file.Close()
		if err != nil {
			fmt.Println("Warning: cannot close plain-text file")
			fmt.Println(err)
		}
		err = os.Remove(file.Name())
		if err != nil {
			fmt.Println("Warning: cannot remove plain-text file")
			fmt.Println(err)
		}

	}

	// removeEncryptedTemp cleans up tempFileEnc on every error path below once it exists:
	// previously, once os.CreateTemp had succeeded, any later error - a failed encrypt, a
	// failed seek, or a failed close/remove of the plain-text source (e.g. because a concurrent
	// caller for the same chunk id already removed it) - returned without ever closing or
	// removing this fully-encrypted temp file, leaking it on disk until the periodic sweep.
	var removeEncryptedTemp = func(tempFileEnc *os.File) {
		if tempFileEnc == nil {
			return
		}
		err := tempFileEnc.Close()
		if err != nil {
			fmt.Println("Warning: cannot close encrypted temp file")
			fmt.Println(err)
		}
		err = os.Remove(tempFileEnc.Name())
		if err != nil {
			fmt.Println("Warning: cannot remove encrypted temp file")
			fmt.Println(err)
		}
	}

	_, err := file.Seek(0, io.SeekStart)
	if err != nil {
		removePlainTextTemp()
		return nil, err
	}
	tempFileEnc, err := os.CreateTemp(configuration.Get().DataDir, "upload")
	if err != nil {
		removePlainTextTemp()
		return nil, err
	}
	encInfo := metadata.Encryption
	err = encryption.Encrypt(&encInfo, file, tempFileEnc)
	if err != nil {
		removePlainTextTemp()
		removeEncryptedTemp(tempFileEnc)
		return nil, err
	}
	_, err = tempFileEnc.Seek(0, io.SeekStart)
	if err != nil {
		removePlainTextTemp()
		removeEncryptedTemp(tempFileEnc)
		return nil, err
	}
	metadata.Encryption = encInfo
	err = file.Close()
	if err != nil {
		removeEncryptedTemp(tempFileEnc)
		return nil, err
	}
	err = os.Remove(file.Name())
	if err != nil {
		removeEncryptedTemp(tempFileEnc)
		return nil, err
	}
	return tempFileEnc, nil
}

func createNewMetaData(hash string, fileHeader chunking.FileHeader, userId int, params models.UploadParameters) models.File {
	file := models.File{
		Id:                 createNewId(),
		Name:               fileHeader.Filename,
		SHA1:               hash,
		Size:               helper.ByteCountSI(fileHeader.Size),
		SizeBytes:          fileHeader.Size,
		ContentType:        fileHeader.ContentType,
		ExpireAt:           params.ExpiryTimestamp,
		UploadDate:         time.Now().Unix(),
		DownloadsRemaining: params.AllowedDownloads,
		UnlimitedTime:      params.UnlimitedTime,
		UnlimitedDownloads: params.UnlimitedDownload,
		PasswordHash:       configuration.HashPassword(params.Password, false, ""),
		UserId:             userId,
		UploadRequestId:    params.FileRequestId,
		BundleId:           params.BundleId,
	}
	file.EncryptedSharePassword = encryptSharePasswordIfEnabled(params)
	if params.IsEndToEndEncrypted {
		file.Encryption = models.EncryptionInfo{IsEndToEndEncrypted: true, IsEncrypted: true}
		file.Size = helper.ByteCountSI(params.RealSize)
	}
	if isEncryptionRequested() {
		file.Encryption.IsEncrypted = true
	}
	if aws.IsAvailable() {
		if !configuration.Get().PicturesAlwaysLocal || !isPictureFile(file.Name, file.ContentType) {
			aws.AddBucketName(&file)
		}
	}
	AddHotlink(&file)
	return file
}

// encryptSharePasswordIfEnabled returns the encrypted form of params.Password to store on the
// new file's EncryptedSharePassword, or nil if it must not be stored.
func encryptSharePasswordIfEnabled(params models.UploadParameters) []byte {
	return EncryptSharePassword(params.Password)
}

// EncryptSharePassword returns the encrypted form of password to store on a file's
// EncryptedSharePassword, or nil if it must not be stored.
//
// Storing it requires: the operator opted in (configuration.StoreShareKeys), a password was set
// at all, and the server master key is available to encrypt it with
// (encryption.IsDecryptionAvailable - false for NoEncryption or EndToEndEncryption instances,
// and for a sealed one). Any encryption failure is treated the same as "master key unavailable":
// the feature no-ops rather than failing the upload.
//
// A password the uploader TYPED is stored on the same terms as a generated one, so that the
// owner can look up any key they set rather than only the ones this app minted. The tradeoff is
// deliberate and was accepted knowingly: a typed password is more likely to be one the uploader
// uses elsewhere, and this keeps it recoverable to anyone who can both reach
// /api/files/{id}/sharekey and unseal the instance. The upload form does NOT say so - it used to,
// until the notice was dropped, and the decision was to keep storing regardless rather than
// restore it. To go back to the previous "generated keys only" rule, gate this on the caller's
// GeneratedPassword signal, which is still parsed and carried end to end but read by nothing.
//
// Exported for the edit path (apiEditFile), which changes a password without going through
// UploadParameters at all. That path MUST call this on every password change and store the
// result even when it is nil: leaving a previously stored key in place after the password has
// been changed makes GET /api/files/{id}/sharekey serve a key that no longer opens the file,
// which is worse than serving none.
func EncryptSharePassword(password string) []byte {
	if !configuration.Get().StoreShareKeys || password == "" {
		return nil
	}
	encrypted, err := encryption.EncryptString(password)
	if err != nil {
		return nil
	}
	return encrypted
}

// GetSharePassword returns the decrypted share password stored for file, if any. The bool
// return is false whenever the plaintext cannot or must not be returned - the feature toggle is
// off, no key was ever stored for this file (e.g. it has no password at all, or was uploaded
// before the feature was enabled), or the server master key is unavailable -
// all collapsed into the same signal so a caller cannot distinguish "off" from "no master key"
// from "nothing stored" (see the /api/files/{id}/sharekey endpoint, which must not become an
// oracle for any of those).
func GetSharePassword(file models.File) (string, bool) {
	return decryptStoredSharePassword(file.EncryptedSharePassword)
}

// GetBundleSharePassword returns the decrypted share password stored for bundle, if any. Mirrors
// GetSharePassword exactly (see that function's doc comment for the full reasoning, which applies
// unchanged here) - the /api/folder/{id}/sharekey endpoint must not become an oracle for "toggle
// off" vs "no master key" vs "nothing stored" any more than the file endpoint may.
func GetBundleSharePassword(bundle models.FileBundle) (string, bool) {
	return decryptStoredSharePassword(bundle.EncryptedSharePassword)
}

func decryptStoredSharePassword(encrypted []byte) (string, bool) {
	if !configuration.Get().StoreShareKeys || len(encrypted) == 0 {
		return "", false
	}
	plaintext, err := encryption.DecryptString(encrypted)
	if err != nil {
		return "", false
	}
	return plaintext, true
}

// createNewId returns a random ID
func createNewId() string {
	return helper.GenerateRandomString(configuration.GetEnvironment().LengthId)
}

func deleteTempFile(file *os.File, hasBeenRenamed *bool) {
	if file != nil && !*hasBeenRenamed {
		err := file.Close()
		helper.Check(err)
		err = os.Remove(file.Name())
		helper.Check(err)
	}
}

const (
	// ParamExpiry is a bit to indicate that the time remaining shall be changed after a duplication
	ParamExpiry int = 1 << iota
	// ParamDownloads is a bit to indicate that the downloads remaining shall be changed after a duplication
	ParamDownloads
	// ParamPassword is a bit to indicate that the password shall be changed after a duplication
	ParamPassword
	// ParamName is a bit to indicate that the filename shall be changed after a duplication
	ParamName
)

// ReplaceFile replaces the file content of fileId with the content of newFileContentId
// If delete is true, the NEW file will be deleted.
// Replacing e2e encrypted files is NOT possible
func ReplaceFile(fileId, newFileContentId string, delete bool) (models.File, error) {
	file, ok := GetFile(fileId)
	if !ok {
		return models.File{}, ErrorFileNotFound
	}
	newFileContent, ok := GetFile(newFileContentId)
	if !ok {
		return models.File{}, ErrorFileNotFound
	}
	if file.Encryption.IsEndToEndEncrypted || newFileContent.Encryption.IsEndToEndEncrypted {
		return models.File{}, ErrorReplaceE2EFile
	}

	file.Name = newFileContent.Name
	file.Size = newFileContent.Size
	file.SHA1 = newFileContent.SHA1
	file.ContentType = newFileContent.ContentType
	file.AwsBucket = newFileContent.AwsBucket
	file.SizeBytes = newFileContent.SizeBytes
	file.Encryption = newFileContent.Encryption
	database.SaveMetaData(file)
	if delete {
		DeleteFile(newFileContent.Id, true)
	}
	return file, nil
}

func isChangeRequested(parametersToChange, parameter int) bool {
	return parametersToChange&parameter != 0
}

// DuplicateFile creates a copy of an existing file with new parameters
//
// The duplicate deliberately keeps sharing the source file's storage blob and, if encrypted, its
// key and nonce (via copier.Copy below). This is unrelated to the content-hash deduplication that
// NewFile/NewFileFromChunk perform between independent uploads: here the "second copy" is known by
// construction to be byte-identical to the first, since it is the same already-stored file, not
// attacker-supplied content that merely happens to produce the same hash. Reusing the blob and key
// is therefore safe and does not depend on SHA-1 collision resistance.
func DuplicateFile(file models.File, parametersToChange int, newFileName string, fileParameters models.UploadParameters) (models.File, error) {

	// apiDuplicateFile expects fileParameters.IsEndToEndEncrypted and fileParameters.RealSize not to be used,
	// change in apiDuplicateFile if using in this function!

	var newFile models.File
	err := copier.Copy(&newFile, &file)
	if err != nil {
		return models.File{}, err
	}

	changeExpiry := isChangeRequested(parametersToChange, ParamExpiry)
	changeDownloads := isChangeRequested(parametersToChange, ParamDownloads)
	changePassword := isChangeRequested(parametersToChange, ParamPassword)
	changeName := isChangeRequested(parametersToChange, ParamName)

	if changeExpiry {
		newFile.ExpireAt = fileParameters.ExpiryTimestamp
		newFile.UnlimitedTime = fileParameters.UnlimitedTime
	}
	if changeDownloads {
		newFile.DownloadsRemaining = fileParameters.AllowedDownloads
		newFile.UnlimitedDownloads = fileParameters.UnlimitedDownload
	}
	if changePassword {
		// changePassword is only true when the caller (apiDuplicateFile) determined that a
		// password header was actually present in the request, so isPresent is always true
		// here - see paramFilesDuplicate.ProcessParameter in routing.go.
		validatedPassword, err := configuration.ValidateSharePassword(fileParameters.Password, true)
		if err != nil {
			return models.File{}, err
		}
		newFile.PasswordHash = configuration.HashPassword(validatedPassword, false, "")
		// Always reassigned, never inherited. newFile is a copy of the source, so without this
		// the duplicate keeps the SOURCE's stored key while carrying its own new password hash -
		// and GET /files/{id}/sharekey would then hand the duplicate's owner, who can be a
		// different user (UserId is reassigned below), the source file's password. Stored on the
		// same terms as every other password change; see EncryptSharePassword, whose contract is
		// that a caller changing a password must store its result even when that result is nil.
		newFile.EncryptedSharePassword = EncryptSharePassword(validatedPassword)
	}
	if changeName {
		newFile.Name = newFileName
	}

	newFile.Id = createNewId()
	newFile.DownloadCount = 0
	newFile.UserId = fileParameters.UserId
	newFile.BundleId = ""
	AddHotlink(&newFile)

	database.SaveMetaData(newFile)
	return newFile, nil
}

func hashFile(input io.Reader, useSalt bool) (string, error) {
	hash := sha1.New()
	_, err := io.Copy(hash, input)
	if err != nil {
		return "", err
	}
	if useSalt {
		hash.Write([]byte(configuration.Get().Authentication.SaltFiles))
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// Generates the storage identifier of an uploaded file and returns a reader for the file, the
// identifier and if a temporary file was created the reference to that file. An unencrypted upload
// is identified by the hex-encoded SHA1 hash of its content, which allows it to be deduplicated. A
// file that is encrypted server-side is never deduplicated (see NewFile) and is instead given a
// random identifier, the same way getChunkFileHash does for chunked uploads.
func generateHashAndEncrypt(fileContent io.Reader, fileHeader *multipart.FileHeader) (io.Reader, string, *os.File, models.EncryptionInfo) {
	hash := sha1.New()
	encInfo := models.EncryptionInfo{}
	if fileHeader.Size <= int64(configuration.Get().MaxMemory)*1024*1024 {
		content, err := io.ReadAll(fileContent)
		helper.Check(err)
		hash.Write(content)
		if isEncryptionRequested() {
			encContent := new(bytes.Buffer)
			err = encryption.Encrypt(&encInfo, bytes.NewReader(content), encContent)
			helper.Check(err)
			return bytes.NewReader(encContent.Bytes()), newEncryptedFileId(), nil, encInfo
		}
		return bytes.NewReader(content), hex.EncodeToString(hash.Sum(nil)), nil, encInfo
	}
	tempFile, err := os.CreateTemp(configuration.Get().DataDir, "upload")
	helper.Check(err)
	var multiWriter io.Writer

	multiWriter = io.MultiWriter(tempFile, hash)
	_, err = io.Copy(multiWriter, fileContent)
	helper.Check(err)
	_, err = tempFile.Seek(0, io.SeekStart)
	helper.Check(err)

	if isEncryptionRequested() {
		tempFileEnc, err := os.CreateTemp(configuration.Get().DataDir, "upload")
		helper.Check(err)
		err = encryption.Encrypt(&encInfo, tempFile, tempFileEnc)
		helper.Check(err)
		err = os.Remove(tempFile.Name())
		helper.Check(err)
		return tempFileEnc, newEncryptedFileId(), tempFileEnc, encInfo
	}
	// Instead of returning a reference to the file as the 3rd result, one could use reflections. However, that would be more expensive.
	return tempFile, hex.EncodeToString(hash.Sum(nil)), tempFile, encInfo
}

func isEncryptionRequested() bool {
	switch configuration.Get().Encryption.Level {
	case encryption.NoEncryption:
		return false
	case encryption.LocalEncryptionStored, encryption.LocalEncryptionInput:
		return !aws.IsAvailable()
	case encryption.FullEncryptionStored, encryption.FullEncryptionInput:
		return true
	case encryption.EndToEndEncryption:
		return false
	default:
		log.Fatalln("Unknown encryption level requested")
		return false
	}
}

// imageFileExtensions contains all known image extensions that can be used for hotlinks
var imageFileExtensions = []string{".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tiff", ".tif", ".ico", ".avif", ".avifs", ".apng"}

// videoFileExtensions contains all known video extensions that can be used for hotlinks, if enabled with the env var ENABLE_HOTLINK_VIDEOS
var videoFileExtensions = []string{".3gp", ".avi", ".flv", ".m4v", ".mkv", ".mov", ".mp4", ".mpg", ".mpeg", ".ts", ".webm", ".wmv"}

// AddHotlink will first check if the file may use a hotlink (e.g. not encrypted or password-protected).
// If file is an image, it will generate a new hotlink in the database and add it to the parameter file
// Otherwise no changes will be made
func AddHotlink(file *models.File) {
	if !IsAbleHotlink(*file) {
		return
	}
	link := helper.GenerateRandomString(configuration.GetEnvironment().LengthHotlinkId) + getFileExtension(file.Name)
	file.HotlinkId = link
	database.SaveHotlink(*file)
}

// IsAbleHotlink returns true, if the file may use hotlinks (e.g. an image file that is not encrypted or password-protected).
func IsAbleHotlink(file models.File) bool {
	env := environment.New()
	if env.DisableHotlinks {
		return false
	}
	if file.RequiresClientDecryption() {
		return false
	}
	if file.PasswordHash != "" {
		return false
	}
	// A hotlink is an unauthenticated direct URL to the bytes, so it is a way
	// around the recipient list entirely. Refused for the same reason an
	// encrypted or password-protected file is.
	if database.IsShareRestricted(models.ShareResourceFile, file.Id) {
		return false
	}
	if strings.Contains(strings.ToLower(file.ContentType), "image/svg") {
		return false
	}
	if isPictureFile(file.Name, file.ContentType) {
		return true
	}
	if !env.HotlinkVideos {
		return false
	}
	return isVideoFile(file.Name, file.ContentType)
}

// getFileExtension returns the file extension of a filename in lowercase
func getFileExtension(filename string) string {
	return strings.ToLower(filepath.Ext(filename))
}

// isPictureFile returns true if it has one of the supported extensions saved in imageFileExtensions
func isPictureFile(filename, contentType string) bool {
	if !strings.HasPrefix(strings.ToLower(contentType), "image/") {
		return false
	}
	extension := strings.ToLower(getFileExtension(filename))
	return helper.IsInArray(imageFileExtensions, extension)
}

func isVideoFile(filename, contentType string) bool {
	if !strings.HasPrefix(strings.ToLower(contentType), "video/") {
		return false
	}
	extension := getFileExtension(filename)
	return helper.IsInArray(videoFileExtensions, extension)
}

// GetFile gets the file by id. Returns (empty File, false) if invalid / expired file
// or (file, true) if valid file
func GetFile(id string) (models.File, bool) {
	var emptyResult = models.File{}
	if id == "" {
		return emptyResult, false
	}
	file, ok := database.GetMetaDataById(id)
	if !ok {
		return emptyResult, false
	}
	if file.IsPendingForDeletion() {
		return emptyResult, false
	}
	// A disposed record is owner-visible history and nothing else: every public path treats it
	// exactly like a record that was deleted outright. GetFile is the single choke point every
	// public path (download, hotlink, share resend, ...) resolves a file through, so the check
	// belongs here rather than duplicated at each caller.
	if file.IsDisposed() {
		return emptyResult, false
	}
	if IsExpiredFile(file, time.Now().Unix()) {
		return emptyResult, false
	}
	if !checkIfValidAws(file) {
		return emptyResult, false
	}
	if !FileExists(file, configuration.Get().DataDir) {
		return emptyResult, false
	}
	return file, true
}

func checkIfValidAws(file models.File) bool {
	return file.IsLocalStorage() || aws.IsAvailable()
}

// GetFileByHotlink gets the file by hotlink id. Returns (empty File, false) if invalid / expired file
// or (file, true) if valid file
func GetFileByHotlink(id string) (models.File, bool) {
	var emptyResult = models.File{}
	if id == "" {
		return emptyResult, false
	}
	fileId, ok := database.GetHotlink(id)
	if !ok {
		return emptyResult, false
	}
	return GetFile(fileId)
}

// ServeFile subtracts a download allowance and serves the file to the browser
// Returns false if the file expired during the request (most likely race condition due to parallel downloads, requires recheckExpiry)
func ServeFile(file models.File, w http.ResponseWriter, r *http.Request, forceDownload, increaseCounter, forceDecryption, recheckExpiry bool) bool {
	// A server-side encrypted file (i.e. not end-to-end encrypted, where the server never holds
	// a key capable of decrypting it anyway) cannot be served while the instance is sealed: doing
	// so would eventually call into encryption.GetCipherFromFile/DecryptReader with no master key
	// loaded. Refused here, before the download allowance below is touched, rather than letting
	// that call fail deep inside encryption/decryption. Written and returned exactly like the
	// audit-write-failure case further down: the status is sent directly, and true is returned so
	// none of the callers additionally render an "expired" page/image over the top of it.
	if file.Encryption.IsEncrypted && !file.Encryption.IsEndToEndEncrypted && encryption.IsSealed() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("This server instance is sealed and cannot serve encrypted files until an administrator unseals it."))
		return true
	}
	// apimutex only serialises this section within the current process; it is a local fast-path that
	// avoids unnecessary database round trips under in-process contention. The invariant that a capped
	// file cannot be downloaded more times than allowed is now enforced by the database itself (see
	// database.IncreaseDownloadCount), which stays correct even across multiple instances sharing one DB.
	apimutex.Lock(apimutex.TypeMetaData, file.Id)
	if recheckExpiry {
		// Re-read the row rather than trusting the caller's copy: the allowance and the download
		// window may both have moved since it was fetched, and both decide whether this request
		// may still be served.
		current, ok := database.GetMetaDataById(file.Id)
		if !ok {
			apimutex.Unlock(apimutex.TypeMetaData, file.Id)
			return false
		}
		file.DownloadsRemaining = current.DownloadsRemaining
		file.WindowOpenedAt = current.WindowOpenedAt
	}
	// The axes governing this file, resolved once - after any re-read above - and read by both
	// decisions below: whether this request may still be served, and which counter serving it
	// spends. Skipped when the caller asks for neither, since resolving it costs a read.
	var access models.DownloadAccess
	if recheckExpiry || increaseCounter {
		access = DownloadAccessOf(file)
	}
	if recheckExpiry {
		// Only the expiry is re-tested when another counter governs. That counter was spent
		// atomically by the caller that gated this request - the recipient's own grant, the
		// folder's visit allowance - so re-testing it here would find the download acquired for
		// this very request already accounted for, and refuse to deliver what was just paid for.
		// Where this function is the one that spends, it re-tests both, exactly as before.
		if access.IsExpired(time.Now().Unix()) {
			apimutex.Unlock(apimutex.TypeMetaData, file.Id)
			return false
		}
		if access.SpendsOwnCounter && access.IsExhausted(time.Now().Unix()) {
			apimutex.Unlock(apimutex.TypeMetaData, file.Id)
			return false
		}
	}
	if increaseCounter {
		// Which counter a download spends is downloadAccessOf's decision, not this function's.
		// A file governed by its folder, or by the per-recipient grants of a share restricted to
		// named recipients, has already had that counter spent by whoever gated the request, and
		// its own must be left untouched - otherwise a file limited to three downloads and
		// shared with three people would still stop after three, locking out the two recipients
		// who never got theirs. All that is left to record here is that it was downloaded.
		if access.SpendsOwnCounter && !access.UnlimitedDownloads {
			granted, opened := database.AcquireDownload(file.Id, time.Now().Unix(), int64(LeewayFor(file).Seconds()))
			if !granted {
				// The allowance is exhausted and no download window is open (or the atomic,
				// floored decrement lost the race and the winner's window has since closed) -
				// this caller must not serve the file, regardless of what the pre-fetched file
				// struct says.
				apimutex.Unlock(apimutex.TypeMetaData, file.Id)
				return false
			}
			// A request served inside an already-open window spends nothing: it is the same
			// pickup as the one that opened it, retried or resumed.
			if opened {
				file.DownloadsRemaining = file.DownloadsRemaining - 1
				file.DownloadCount = file.DownloadCount + 1
				go sse.PublishDownloadCount(file)
			}
		} else {
			database.IncreaseDownloadCount(file.Id)
			file.DownloadCount = file.DownloadCount + 1
			go sse.PublishDownloadCount(file)
		}
	}
	apimutex.Unlock(apimutex.TypeMetaData, file.Id)

	// Fail closed: the audit record for this download is committed (fsync'd) to durable local
	// storage before any bytes are served below, and the request is refused if that write
	// fails - so a crash between the two can only over-log (an audit entry for a download that
	// did not fully complete), never serve content with no record of it. See
	// internal/logging/AuditLog.go for the chain design.
	//
	// Note the increaseCounter block above already ran: if increaseCounter was
	// set, this file's download allowance was already decremented before this point, so a
	// failure here is an irreversible state change with no audit record of it - not merely a
	// refused request. logging.LogAuditWriteFailure is a best-effort attempt to still record
	// that fact via the separate human-readable log, since the two are independent files.
	if err := logging.LogDownload(file, r, configuration.Get().SaveIp); err != nil {
		if increaseCounter {
			logging.LogAuditWriteFailure(fmt.Sprintf("download allowance for file %s was already decremented", file.Id), err)
		}
		fmt.Println("audit: refusing download, could not record audit event:", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("Service temporarily unavailable, please try again."))
		return true
	}
	go serverstats.AddTraffic(uint64(file.SizeBytes))

	if !file.IsLocalStorage() {
		// If non-blocking, we are not setting a download complete status as there is no reliable way to
		// confirm that the file has been completely downloaded. It expires automatically after 24 hours.
		statusId := downloadstatus.SetDownload(file)
		isBlocking, err := aws.ServeFile(w, r, file, forceDownload, forceDecryption)
		// TODO chances are high that an error is returned here, we should consider proper output
		helper.Check(err)
		if isBlocking {
			downloadstatus.SetComplete(statusId)
		}
		return true
	}
	fileHandler, _, err := getFileHandler(file, configuration.Get().DataDir)
	defer fileHandler.Close()
	if err != nil {
		fmt.Println(err)
		_, _ = w.Write([]byte("Error getting file handler"))
		return true
	}
	if file.Encryption.IsEncrypted && !file.RequiresClientDecryption() {
		if !encryption.IsCorrectKey(file.Encryption, fileHandler) {
			_, _ = w.Write([]byte("Internal error - Error decrypting file, source data might be damaged or an incorrect key has been used"))
			return true
		}
	}
	statusId := downloadstatus.SetDownload(file)
	headers.Write(file, w, forceDownload, false)
	if file.Encryption.IsEncrypted && !file.RequiresClientDecryption() {
		err = encryption.DecryptReader(file.Encryption, fileHandler, w)
		if err != nil {
			_, _ = w.Write([]byte("Error decrypting file"))
			fmt.Println(err)
			return true
		}
	} else {
		http.ServeContent(w, r, file.Name, time.Now(), fileHandler)
	}
	downloadstatus.SetComplete(statusId)
	return true
}

// Returns the filename if unique or a new filename in the format "Name (x).ext"
func makeFilenameUnique(filename string, nameMap *map[string]bool) string {
	ext := filepath.Ext(filename)
	base := strings.TrimSuffix(filename, ext)
	if !(*nameMap)[filename] {
		(*nameMap)[filename] = true
		return filename
	}

	count := 2
	for {
		newName := fmt.Sprintf("%s (%d)%s", base, count, ext)
		if !(*nameMap)[newName] {
			(*nameMap)[newName] = true
			return newName
		}
		count++
	}
}

// ServeFilesAsZip will zip all files and serve them to the browser. Can decrypt files if not end-to-end encrypted.
func ServeFilesAsZip(files []models.File, filename string, w http.ResponseWriter, r *http.Request) {
	// Checked - and refused, before any header is written - for the same reason as the identical
	// guard at the top of ServeFile: a server-side encrypted member file cannot be decrypted while
	// the instance is sealed, and letting the zip stream start before finding that out would leave
	// the client with a truncated, half-written archive instead of a clean refusal.
	if encryption.IsSealed() {
		for _, file := range files {
			if file.Encryption.IsEncrypted && !file.Encryption.IsEndToEndEncrypted {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte("This server instance is sealed and cannot serve encrypted files until an administrator unseals it."))
				return
			}
		}
	}
	if filename == "" {
		filename = "Gokapi"
	}
	filename = helper.SanitiseFilename(filename)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.zip\"", filename))
	w.WriteHeader(http.StatusOK)

	saveIp := configuration.Get().SaveIp
	zipWriter := zip.NewWriter(w)
	defer zipWriter.Close()
	filenames := make(map[string]bool)
	for _, file := range files {
		file.Name = makeFilenameUnique(file.Name, &filenames)
		// Fail closed: the HTTP status for this response was already sent above to start the
		// zip stream, so a 503 can no longer be returned if the audit write fails. Instead,
		// this file (and the zip stream entirely) is not written, leaving the client with a
		// truncated - and therefore visibly invalid - zip rather than a complete one containing
		// a file with no durable audit record.
		if err := logging.LogDownload(file, r, saveIp); err != nil {
			fmt.Println("audit: aborting zip download, could not record audit event for", file.Id, ":", err)
			return
		}
		header := &zip.FileHeader{
			Name:     file.Name,
			Method:   zip.Store,
			Modified: time.Unix(file.UploadDate, 0),
		}
		entryWriter, err := zipWriter.CreateHeader(header)
		helper.Check(err)
		go serverstats.AddTraffic(uint64(file.SizeBytes))
		if !file.IsLocalStorage() {
			statusId := downloadstatus.SetDownload(file)
			err = aws.Stream(entryWriter, file)
			helper.Check(err)
			downloadstatus.SetComplete(statusId)
			_ = zipWriter.Flush()
			flushingWriter, ok := w.(http.Flusher)
			if ok {
				flushingWriter.Flush()
			}
			continue
		}
		fileHandler, _, err := getFileHandler(file, configuration.Get().DataDir)
		if err != nil {
			fmt.Println(err)
			_, _ = w.Write([]byte("Error getting file handler"))
			return
		}
		statusId := downloadstatus.SetDownload(file)
		if file.Encryption.IsEncrypted {
			if !encryption.IsCorrectKey(file.Encryption, fileHandler) {
				_, _ = w.Write([]byte("Internal error - Error decrypting file, source data might be damaged or an incorrect key has been used"))
				_ = fileHandler.Close()
				return
			}
			err = encryption.DecryptReader(file.Encryption, fileHandler, entryWriter)
			if err != nil {
				_, _ = w.Write([]byte("Error decrypting file"))
				fmt.Println(err)
				_ = fileHandler.Close()
				return
			}
		} else {
			_, err = io.Copy(entryWriter, fileHandler)
			helper.Check(err)
			_ = fileHandler.Close()
		}
		downloadstatus.SetComplete(statusId)
		_ = zipWriter.Flush()
		flushingWriter, ok := w.(http.Flusher)
		if ok {
			flushingWriter.Flush()
		}
	}
}

func getFileHandler(file models.File, dataDir string) (*os.File, int64, error) {
	fileHandler, err := os.OpenFile(dataDir+"/"+file.SHA1, os.O_RDONLY, 0644)
	if err != nil {
		return nil, 0, err
	}
	size, err := helper.GetFileSize(fileHandler)
	if err != nil {
		return nil, 0, err
	}
	return fileHandler, size, nil
}

// FileExists checks if the file exists locally or in S3
func FileExists(file models.File, dataDir string) bool {
	if !file.IsLocalStorage() {
		exists, size, err := aws.FileExists(file)
		if err != nil {
			fmt.Println("Warning, cannot check file " + file.Id + ": " + err.Error())
			return true
		}
		if !exists {
			return false
		}
		if size == 0 && file.Size != "0 B" {
			return false
		}
		return true
	}
	exists, err := helper.FileExists(dataDir + "/" + file.SHA1)
	helper.Check(err)
	return exists
}

// cleanUpMutex serialises sweeps. Every manual delete starts one in the background (see
// DeleteFile), so two can easily overlap - and two passes over the same rows are never useful,
// only harmful: each decides what to do from a snapshot taken at its own start, so a pass still
// working through a stale snapshot writes a disposed record back after a faster one has already
// purged it. That resurrected row is gone again a moment later, but for as long as it is there it
// names its bundle, and a bundle is kept alive by exactly that (see cleanInvalidBundles) - so an
// overlapping pair can leave a folder behind that neither pass on its own would have. DeleteFiles
// already batches deletions to keep passes from piling up; this makes that hold for every caller.
var cleanUpMutex sync.Mutex

// CleanUp disposes of expired, exhausted or owner-deleted files, purges disposed records once
// their retention window has elapsed, and removes files whose stored content has gone missing
// outright. Will be called periodically or after a file has been manually deleted in the admin
// view. If the parameter periodic is true, this function is recursive and calls itself every
// hour.
//
// One pass, first match wins, per file:
//  1. its pending deletion timer elapsed and it is not currently downloading -> dispose of it,
//     reason "deleted"
//  2. it is already disposed of and past the retention window -> purge the record
//  3. it is already disposed of (but not past retention) -> skip entirely, not even a stat call
//  4. its stored content is missing -> hard delete; corruption is not history, so this bypasses
//     retention and disposal both
//  5. it is expired or its downloads are exhausted, and it is not currently downloading ->
//     dispose of it, reason "downloaded" if the downloads ran out, else "expired"; if retention
//     is disabled, purge it in the same step
//
// The SHA1 reference count below is computed once per pass, over every row that is not already
// disposed of: a disposed row holds no content of its own anymore, so it must be structurally
// incapable of protecting another row's blob from deletion. It is decremented as rows in this
// pass are disposed of, so that two rows sharing a blob and expiring in the same pass still only
// have it deleted once, on whichever of them is processed last.
func CleanUp(periodic bool) {
	cleanUpMutex.Lock()
	defer cleanUpMutex.Unlock()
	downloadstatus.Clean()
	timeNow := time.Now().Unix()
	dataDir := configuration.Get().DataDir
	retention := time.Duration(environment.New().MetadataRetention)

	allFiles := database.GetAllMetadata()
	resolver := NewDownloadAccessResolver()
	shaRefCount := make(map[string]int, len(allFiles))
	for _, file := range allFiles {
		if !file.IsDisposed() {
			shaRefCount[file.SHA1]++
		}
	}

	for key, element := range allFiles {
		switch {
		case !element.IsDisposed() && isPendingToBeDeletedWithoutDownload(element, timeNow):
			disposeFile(element, models.DisposalReasonDeleted, "pending deletion timer elapsed", timeNow, dataDir, shaRefCount)
			if retention <= 0 {
				purgeFile(key, "metadata retention is disabled")
			}
		case element.IsDisposed():
			if retention > 0 && timeNow-element.DisposedAt >= int64(retention.Seconds()) {
				purgeFile(key, "metadata retention window elapsed")
			}
			// Not yet past retention: skip entirely, including the FileExists stat below - the
			// content is already gone, so there is nothing to check.
		case !FileExists(element, dataDir):
			deleteFileHard(element, key, "stored object missing")
		case isExpiredFileWithoutDownload(element, resolver.Of(element), timeNow):
			reason := models.DisposalReasonExpired
			reasonText := "expired"
			if resolver.Of(element).IsExhausted(timeNow) {
				reason = models.DisposalReasonDownloaded
				reasonText = "downloads exhausted"
			}
			disposeFile(element, reason, reasonText, timeNow, dataDir, shaRefCount)
			if retention <= 0 {
				purgeFile(key, "metadata retention is disabled")
			}
		}
	}
	cleanOldTempFiles()
	cleanHotlinks()
	purgeHotlinksIfDisabled()
	cleanInvalidApiKeys()
	cleanInvalidFileRequests()
	cleanExpiredFileRequests()
	cleanInvalidBundles()
	database.CleanUpExpiredShareLoginTokens(timeNow)
	cleanOrphanShareGrants()
	database.RunGarbageCollection()

	if periodic {
		go func() {
			time.Sleep(time.Hour)
			CleanUp(periodic)
		}()
	}
}

func getUserMap() map[int]models.User {
	result := make(map[int]models.User)
	users := database.GetAllUsers()
	for _, user := range users {
		result[user.Id] = user
	}
	return result
}

// cleanInvalidApiKeys removes all API keys that are not associated with a user anymore
// Normally this should not be a problem, but if a user was manually deleted from the database,
// this could cause issues otherwise.
func cleanInvalidApiKeys() {
	users := getUserMap()
	for _, apiKey := range database.GetAllApiKeys() {
		_, exists := users[apiKey.UserId]
		if !exists {
			database.DeleteApiKey(apiKey.Id)
			continue
		}
		if apiKey.IsUploadRequestKey() {
			_, exists = database.GetFileRequest(apiKey.UploadRequestId)
			if !exists {
				database.DeleteApiKey(apiKey.Id)
			}
		}
	}
}

// cleanInvalidFileRequests removes file requests and the associated files from the database if their associated owner is not a valid user.
// Normally this should not be a problem, but if a user was manually deleted from the database,
// this could cause issues otherwise.
func cleanInvalidFileRequests() {
	users := getUserMap()
	for _, fileRequest := range database.GetAllFileRequests() {
		_, exists := users[fileRequest.UserId]
		if !exists {
			files := database.GetAllMetadata()
			for _, file := range files {
				if file.UploadRequestId == fileRequest.Id {
					DeleteFile(file.Id, true)
				}
			}
			database.DeleteFileRequest(fileRequest)
		}

	}
}

// DeleteFileRequest deletes a file request together with every file it received and its upload
// API key. This is the one place that cascade is implemented: filerequest.Delete delegates here
// rather than assembling the same three steps itself, because storage/filerequest imports this
// package for DeleteFiles - a dependency the other direction would make circular, which is also
// why cleanExpiredFileRequests below calls this directly instead of going through
// storage/filerequest.
func DeleteFileRequest(request models.FileRequest) {
	var files []models.File
	for _, file := range database.GetAllMetadata() {
		if file.UploadRequestId == request.Id {
			files = append(files, file)
		}
	}
	DeleteFiles(files, true)
	database.DeleteFileRequest(request)
	database.DeleteApiKey(request.ApiKey)
}

// cleanExpiredFileRequests deletes file requests, and everything DeleteFileRequest cascades to,
// once they have been expired or closed for at least GOKAPI_FILEREQUEST_RETENTION. Skipped
// entirely when that is 0, the default: nothing an existing install already holds is removed by
// upgrading, only what an operator explicitly opts into by setting the duration.
//
// A request's clock starts at whichever end state applies to it: Expiry for one that ran out on
// its own, ClosedAt for one closed early. Both are checked independently, so a request that is
// both closed and expired is eligible the moment either window elapses. ClosedAt is 0 for a
// request that has never been closed, and also for one that was closed before this field existed
// (its ALTER TABLE backfill defaults it to 0, the same as FileMetaData.DisposedAt's did) - such a
// request is left for Expiry to catch instead of being treated as closed at the epoch.
func cleanExpiredFileRequests() {
	retention := time.Duration(environment.New().FileRequestRetention)
	if retention <= 0 {
		return
	}
	timeNow := time.Now().Unix()
	retentionSeconds := int64(retention.Seconds())
	for _, request := range database.GetAllFileRequests() {
		expiredPastRetention := request.IsExpired() && timeNow-request.Expiry >= retentionSeconds
		closedPastRetention := request.Closed && request.ClosedAt > 0 && timeNow-request.ClosedAt >= retentionSeconds
		if expiredPastRetention || closedPastRetention {
			DeleteFileRequest(request)
		}
	}
}

// cleanInvalidBundles removes bundles that no file row refers to any more. This is the only place
// a bundle's lifetime is decided, for an owner-deleted folder as much as for an abandoned one:
// filebundle.Delete marks a folder and leaves it here rather than deciding for itself, because it
// would be deciding against a sweep that runs in the background.
//
// A disposed member still has its row, and keeps its bundle alive with it. Metadata retention
// deliberately outlives the content it describes, so a deleted file stays listed for its owner
// (see disposeFile and GOKAPI_METADATA_RETENTION); deleting the folder as soon as its last
// member was disposed of left those rows pointing at a bundle that no longer existed, and the
// file list had nothing left to group them under. The bundle goes when the last member row is
// purged, not when the last member's content is.
//
// A bundle young enough to still be inside models.FileBundleGracePeriod is left alone, since a
// folder whose first upload is still in flight has no member row to be kept alive by yet. A
// folder its owner deleted can gain no members, so that grace is not what it needs and would
// only hold an already-emptied folder in the listing for the rest of the day.
func cleanInvalidBundles() {
	bundles := database.GetAllFileBundles()
	files := database.GetAllMetadata()

	for _, bundle := range bundles {
		if !bundle.IsDeleted() && !bundle.IsOlderThanGracePeriod() {
			continue
		}
		hasMember := false
		for _, file := range files {
			if file.BundleId == bundle.Id {
				hasMember = true
				break
			}
		}
		if !hasMember {
			database.DeleteFileBundle(bundle)
		}
	}
}

// cleanOrphanShareGrants removes share grants whose resource no longer
// exists. This is the safety net for a crash between a resource delete and
// its cascade (see database.DeleteMetaData, DeleteFileBundle,
// DeleteFileRequest, and purgeFile/deleteFileHard above), and it is also the
// one-time backfill for grants that were orphaned before that cascade
// existed: a grant references a resource across three separate tables
// depending on its type, so a schema migration step cannot resolve that, and
// redis has no joins to filter with. Runs on every sweep; cheap at this
// install's scale.
//
// A file that is disposed but not yet purged is NOT an orphan: its metadata
// row still exists deliberately, as owner-visible history (GetMetaDataById
// returns disposed rows same as live ones), and its grants are removed by
// purgeFile once the retention window elapses. Only a resource whose row is
// gone outright counts as orphaned here.
func cleanOrphanShareGrants() {
	for _, recipient := range database.GetAllShareRecipients() {
		for _, grant := range database.GetShareGrantsForRecipient(recipient.Id) {
			if shareResourceExists(grant.ResourceType, grant.ResourceId) {
				continue
			}
			database.DeleteShareGrants(grant.ResourceType, grant.ResourceId)
		}
	}
}

// shareResourceExists reports whether the resource a share grant points at is
// still present, for cleanOrphanShareGrants to decide whether the grant is
// orphaned. A disposed-but-not-purged file still exists by this measure,
// since GetMetaDataById returns it.
func shareResourceExists(resourceType int, resourceId string) bool {
	switch resourceType {
	case models.ShareResourceFile:
		_, exists := database.GetMetaDataById(resourceId)
		return exists
	case models.ShareResourceBundle:
		_, exists := database.GetFileBundle(resourceId)
		return exists
	case models.ShareResourceFileRequest:
		_, exists := database.GetFileRequest(resourceId)
		return exists
	default:
		return false
	}
}

// cleanHotlinks removes hotlinks from the database where the file has expired
func cleanHotlinks() {
	hotlinks := database.GetAllHotlinks()
	for _, hotlink := range hotlinks {
		_, ok := GetFileByHotlink(hotlink)
		if !ok {
			database.DeleteHotlink(hotlink)
		}
	}
}

// purgeHotlinksIfDisabled removes all hotlinks from the database and clears HotlinkId on the
// corresponding file metadata, if hotlinks have been disabled with GOKAPI_DISABLE_HOTLINKS.
// Unlike cleanHotlinks, which only removes hotlinks whose file has already become unavailable,
// this also purges hotlinks that are still valid, so that switching the setting on retroactively
// kills every link that was minted before it was set. As this runs as part of CleanUp, it is
// executed once on startup and every hour after that, which makes it idempotent: once the
// database no longer contains any hotlinks, there is nothing left to purge or clear.
func purgeHotlinksIfDisabled() {
	if !environment.New().DisableHotlinks {
		return
	}
	for _, hotlink := range database.GetAllHotlinks() {
		database.DeleteHotlink(hotlink)
	}
	for _, file := range database.GetAllMetadata() {
		if file.HotlinkId != "" {
			file.HotlinkId = ""
			database.SaveMetaData(file)
		}
	}
}

// cleanOldTempFiles removes temporary chunk or upload files that are older than 24 hours
func cleanOldTempFiles() {
	tmpfiles, err := os.ReadDir(configuration.Get().DataDir)
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, file := range tmpfiles {
		if isOldTempFile(file) {
			err = os.Remove(configuration.Get().DataDir + "/" + file.Name())
			if err != nil {
				fmt.Println(err)
			}
		}
	}
}

// isOldTempFile returns true if a file is older than 24 hours and starts with the name upload or chunk
func isOldTempFile(file os.DirEntry) bool {
	if file.IsDir() {
		return false
	}
	if !strings.HasPrefix(file.Name(), "upload") && !strings.HasPrefix(file.Name(), "chunk-") {
		return false
	}
	info, err := file.Info()
	if err != nil {
		return false
	}
	return time.Now().Sub(info.ModTime()) > 24*time.Hour

}

// isPendingToBeDeleted returns true if a pending deletion has to be executed.
//
// Strictly <, not <=: PendingDeletion can be a genuine future deadline truncated to whole
// seconds by time.Time.Unix() (DeleteFileSchedule with a sub-second delay), which often lands on
// the current second - a <= here would then read that as already elapsed the instant it was set,
// letting CancelPendingFileDeletion refuse a restore that should still have most of a second left
// to run. DeleteFile backdates PendingDeletion by a second for the immediate-delete case (see its
// comment) specifically so it does not need <= here to be picked up promptly.
func isPendingToBeDeleted(file models.File, timeNow int64) bool {
	if !file.IsPendingForDeletion() {
		return false
	}
	return file.PendingDeletion < timeNow
}

// isPendingToBeDeletedWithoutDownload returns true if there is no active download for a file
// whose pending deletion timer has elapsed. Same shape as isExpiredFileWithoutDownload below,
// for the same reason: a download in progress is given the chance to finish before the file's
// content is disposed of out from under it.
func isPendingToBeDeletedWithoutDownload(file models.File, timeNow int64) bool {
	if downloadstatus.IsCurrentlyDownloading(file) {
		return false
	}
	return isPendingToBeDeleted(file, timeNow)
}

// contentTypeSecret is the MIME type a client sends for a text secret or note, and the only thing
// that distinguishes one from any other one-download file once it reaches the server. LeewayFor
// below is the only place it is consulted, which is also why trusting it is safe: claiming it for
// an ordinary file can only shorten that file's own access, never lengthen it or anyone else's.
const contentTypeSecret = "application/x-exchangepoint-secret"

// DownloadLeeway returns how long a download window stays open, GOKAPI_DOWNLOAD_LEEWAY. Re-read on
// every use rather than cached, the same contract GOKAPI_MAX_EXPIRY and GOKAPI_METADATA_RETENTION
// have. This is the policy for a resource that is not a file - a folder, whose window covers every
// member of it at once. For a file, use LeewayFor.
func DownloadLeeway() time.Duration {
	return time.Duration(configuration.GetEnvironment().DownloadLeeway)
}

// LeewayFor returns how long a download window stays open for this file. A secret has none: the
// leeway exists so a broken transfer does not cost the recipient their download, and a secret is
// one short response with nothing to resume.
//
// This is the only function that decides the duration. Every caller passes the value it returns
// and is otherwise identical, so there is one rule - access ends at whichever comes first, the
// expiry or the close of the download window - and only the window's length varies.
func LeewayFor(file models.File) time.Duration {
	if file.ContentType == contentTypeSecret {
		return 0
	}
	return DownloadLeeway()
}

// DownloadAccessOf resolves the axes that decide whether this file may still be downloaded and
// when its content is disposed of, reading its folder from the database when it belongs to one
// and the recipient grants of whichever resource governs it.
// See models.DownloadAccess and downloadAccessOf.
func DownloadAccessOf(file models.File) models.DownloadAccess {
	bundle, hasBundle := governingBundle(file)
	resourceType, resourceId := governingShareResource(file, bundle, hasBundle)
	return downloadAccessOf(file, bundle, hasBundle, database.GetShareGrants(resourceType, resourceId))
}

// DownloadAccessResolver answers DownloadAccessOf's question for many files against one read of
// the folder table and one of the grant table. A caller that walks every file - the owner's file
// list, the CleanUp sweep - would otherwise read the same folder once per member of it, and the
// grants of every file it passes one at a time.
type DownloadAccessResolver struct {
	bundles map[string]models.FileBundle
	grants  map[shareResourceKey][]models.ShareGrant
}

// shareResourceKey identifies the resource a set of grants was written against, so that one read
// of the whole grant table can be indexed by it.
type shareResourceKey struct {
	resourceType int
	resourceId   string
}

// NewDownloadAccessResolver reads every folder and every grant once, for the resolver to answer
// from.
func NewDownloadAccessResolver() DownloadAccessResolver {
	bundles := make(map[string]models.FileBundle)
	for _, bundle := range database.GetAllFileBundles() {
		bundles[bundle.Id] = bundle
	}
	grants := make(map[shareResourceKey][]models.ShareGrant)
	for _, grant := range database.GetAllShareGrants() {
		key := shareResourceKey{resourceType: grant.ResourceType, resourceId: grant.ResourceId}
		grants[key] = append(grants[key], grant)
	}
	return DownloadAccessResolver{bundles: bundles, grants: grants}
}

// Of returns the axes governing this file, the same answer DownloadAccessOf gives.
func (r DownloadAccessResolver) Of(file models.File) models.DownloadAccess {
	var bundle models.FileBundle
	hasBundle := false
	if file.BundleId != "" && file.IsBundleMember(file.BundleId) {
		bundle, hasBundle = r.bundles[file.BundleId]
	}
	resourceType, resourceId := governingShareResource(file, bundle, hasBundle)
	return downloadAccessOf(file, bundle, hasBundle,
		r.grants[shareResourceKey{resourceType: resourceType, resourceId: resourceId}])
}

// governingBundle returns the folder this file is judged by, if it belongs to one.
func governingBundle(file models.File) (models.FileBundle, bool) {
	if file.BundleId == "" || !file.IsBundleMember(file.BundleId) {
		return models.FileBundle{}, false
	}
	return database.GetFileBundle(file.BundleId)
}

// governingShareResource names the resource whose recipient grants govern this file: its folder
// when it belongs to one, the file itself otherwise. That is the same precedence downloadAccessOf
// applies to the expiry and the allowance - the folder is the unit of sharing - so a member is
// never gated by one resource's recipients while being metered against another's.
func governingShareResource(file models.File, bundle models.FileBundle, hasBundle bool) (int, string) {
	if hasBundle {
		return models.ShareResourceBundle, bundle.Id
	}
	return models.ShareResourceFile, file.Id
}

// downloadAccessOf is the one place that decides which axes govern a file. A member's own expiry
// and download allowance are inert while it belongs to a folder (see models.File.IsBundleMember):
// the folder is the unit of sharing, so it is the folder that decides access, exhaustion and
// disposal, for every member of it together. One visit, one window, one folder - a folder whose
// allowance runs out takes all of its members with it on the next sweep, and a member whose own
// stale counter reached zero long ago is not disposed of while its folder still has allowance.
//
// A recipient list then supersedes the download allowance of whichever of the two governs, the
// same way models.File.AccessMode makes it supersede the passcode: the owner's one number is
// each recipient's own budget, so what is left is the sum of what the recipients have left and
// the resource's own counter neither gates nor exhausts it. See models.DownloadAccess.
// WithShareGrants. The expiry is untouched by this - a share still cannot outlive what it points
// at - so access ends at whichever comes first, the expiry or the last recipient's last
// download, and that is the only rule there is.
//
// A folder is never a secret, so its window is always the configured leeway.
func downloadAccessOf(file models.File, bundle models.FileBundle, hasBundle bool, grants []models.ShareGrant) models.DownloadAccess {
	var access models.DownloadAccess
	if hasBundle {
		access = bundle.DownloadAccess(int64(DownloadLeeway().Seconds()))
		// The counter a visit spends is the folder's, never the member's, so serving this file
		// must leave its own row alone - see models.DownloadAccess.SpendsOwnCounter. Cleared
		// here rather than by FileBundle.DownloadAccess, which answers the folder's own question
		// and is where a folder visit reads that its counter IS the one to spend.
		access.SpendsOwnCounter = false
	} else {
		access = file.DownloadAccess(int64(LeewayFor(file).Seconds()))
	}
	if len(grants) == 0 {
		return access
	}
	return access.WithShareGrants(grants)
}

// DownloadAccessOfBundle resolves the axes governing a folder itself, the folder twin of
// DownloadAccessOf and the one place they are decided. A folder restricted to named recipients is
// governed by their grants exactly as a file is: the owner's one number is each recipient's own
// budget, so its own visit allowance neither gates nor exhausts it, and it is over once the last
// recipient is finished or it expires, whichever comes first.
//
// A folder is never a secret, so its window is always the configured leeway.
func DownloadAccessOfBundle(bundle models.FileBundle) models.DownloadAccess {
	access := bundle.DownloadAccess(int64(DownloadLeeway().Seconds()))
	grants := database.GetShareGrants(models.ShareResourceBundle, bundle.Id)
	if len(grants) == 0 {
		return access
	}
	return access.WithShareGrants(grants)
}

// IsAvailableBundle reports whether the folder itself may currently be opened at all: its owner
// has not deleted it, it is not expired, and its download allowance is not exhausted - which, with
// a leeway above 0, includes a folder whose allowance is spent but whose download window is still
// open. It says nothing about membership: a folder with zero members is still "available" by this
// function alone, and callers combine it with their own membership check (see
// webserver.bundleAvailability) because what counts as a member differs by caller (see
// models.File.IsBundleMember).
//
// A deleted folder keeps its row for as long as its disposed members keep theirs (see
// models.FileBundle.DeletedAt), and that retained row must never let anyone back in. Its members
// are disposed of, so the membership check already refuses it, but this says so directly rather
// than leaving the guarantee to depend on what a caller counts as a member.
func IsAvailableBundle(bundle models.FileBundle, timeNow int64) bool {
	if bundle.IsDeleted() {
		return false
	}
	access := DownloadAccessOfBundle(bundle)
	return !access.IsExpired(timeNow) && !access.IsExhausted(timeNow)
}

// IsExpiredFile returns true if the file can no longer be served: the expiry timestamp passed, or
// the download allowance is spent and the download window that spending it opened has closed. A
// member of a folder is judged by its folder, not by itself - see DownloadAccessOf.
func IsExpiredFile(file models.File, timeNow int64) bool {
	access := DownloadAccessOf(file)
	return access.IsExpired(timeNow) || access.IsExhausted(timeNow)
}

// isExpiredFileWithoutDownload returns true if there is no active download for an expired file
func isExpiredFileWithoutDownload(file models.File, access models.DownloadAccess, timeNow int64) bool {
	if downloadstatus.IsCurrentlyDownloading(file) {
		return false
	}
	return access.IsExpired(timeNow) || access.IsExhausted(timeNow)
}

// deleteSource removes the source file from the file system or cloud storage.
func deleteSource(file models.File, dataDir string) {
	var err error
	if !file.IsLocalStorage() {
		_, err = aws.DeleteObject(file)
	} else {
		err = os.Remove(dataDir + "/" + file.SHA1)
	}
	if err != nil {
		fmt.Println("Warning, cannot delete file " + file.Id + ": " + err.Error())
	}
}

// disposeFile deletes a file's stored content - unless shaRefCount shows another, still-live row
// shares the same blob - and strips every field that a retained history row must not carry:
// the dedup hash, the encryption key/nonce, the password hash, the stored share password, any
// hotlink, and every recipient login token issued against it. The record itself is kept and
// marked, not removed; removing it is purgeFile's job, once the retention window has passed.
//
// NameEncryptedRaw and Name are deliberately left untouched, so SaveMetaData's save-back path
// still has what it needs to write the stored name bytes back verbatim rather than blank them -
// see models.File.NameEncryptedRaw.
func disposeFile(file models.File, reason int, reasonText string, timeNow int64, dataDir string, shaRefCount map[string]int) {
	shaRefCount[file.SHA1]--
	if shaRefCount[file.SHA1] <= 0 {
		deleteSource(file, dataDir)
	}
	if file.HotlinkId != "" {
		database.DeleteHotlink(file.HotlinkId)
		file.HotlinkId = ""
	}
	RevokeShareTokens(models.ShareResourceFile, file.Id)
	file.SHA1 = ""
	file.Encryption.DecryptionKey = nil
	file.Encryption.Nonce = nil
	file.PasswordHash = ""
	file.EncryptedSharePassword = nil
	file.DisposedAt = timeNow
	file.DisposalReason = reason
	database.SaveMetaData(file)
	logging.LogFileExpired(file, reasonText)
}

// purgeFile removes a disposed file's history record once its retention window has passed: the
// grants recording who it was shared with, and the metadata row itself. The content is already
// gone - disposeFile deleted it when the record was disposed of - so there is nothing left to
// remove from storage here.
func purgeFile(fileId string, reasonText string) {
	database.DeleteShareGrants(models.ShareResourceFile, fileId)
	database.DeleteMetaData(fileId)
	logging.LogFilePurged(fileId, reasonText)
}

// deleteFileHard removes a file's record and content outright, bypassing disposal and retention
// entirely. Used when the stored content has gone missing on its own - corruption or an
// out-of-band deletion, not something CleanUp did - so there is no content left to have been
// "disposed of" and nothing worth keeping as history.
func deleteFileHard(file models.File, fileId string, reasonText string) {
	if file.HotlinkId != "" {
		database.DeleteHotlink(file.HotlinkId)
	}
	database.DeleteShareGrants(models.ShareResourceFile, fileId)
	database.DeleteMetaData(fileId)
	logging.LogFileExpired(file, reasonText)
}

// RevokeShareTokens revokes every recipient login token issued against a resource. Used when a
// file is disposed of, and when a folder is deleted (see filebundle.Delete): the grant rows
// recording who had access are kept as history, but the tokens that let a recipient actually use
// one must not survive - a retained record carries no credential material.
func RevokeShareTokens(resourceType int, resourceId string) {
	for _, grant := range database.GetShareGrants(resourceType, resourceId) {
		database.RevokeShareLoginTokens(grant.RecipientId, resourceType, resourceId)
	}
}

// DeleteFile is called when an admin requests deletion of a file.
//
// A record that still has content is scheduled for disposal: PendingDeletion is set to one
// second in the past, which the next CleanUp pass - already running near-immediately when
// deleteSource is true - picks up as reason "deleted" and disposes of through the normal
// retention path, exactly like an expired or downloads-exhausted file. Backdated rather than set
// to exactly now: isPendingToBeDeleted compares with a strict <, on purpose (see its comment), so
// a PendingDeletion of precisely time.Now().Unix() would frequently still equal the CleanUp
// goroutine's own timeNow a few instructions later - the two calls are microseconds apart, not a
// full second - and be skipped until some later sweep instead of "near-immediately" as promised
// here. A record that has already been disposed of has nothing left to dispose of, so it is
// purged outright instead - this is what lets an owner clear an entry out of their history early,
// before the retention window elapses on its own ("Remove from History" in the frontend).
//
// Returns true if the file was found and acted on, or false if ID did not exist.
// deleteSource forces a clean-up and will delete the source if it is not
// used by a different file
func DeleteFile(fileId string, deleteSource bool) bool {
	if fileId == "" {
		return false
	}
	file, ok := database.GetMetaDataById(fileId)
	if !ok {
		return false
	}
	if file.IsDisposed() {
		purgeFile(file.Id, "removed by owner")
		return true
	}
	file.PendingDeletion = time.Now().Add(-time.Second).Unix()
	database.SaveMetaData(file)
	downloadstatus.SetAllComplete(file.Id)
	if deleteSource {
		go CleanUp(false)
	}
	return true
}

// DeleteFiles deletes multiple files at once. This avoids race conditions when CleanUp is called multiple times
// deleteSource forces a clean-up and will delete the source if it is not
// used by a different file
func DeleteFiles(files []models.File, deleteSource bool) {
	for _, file := range files {
		DeleteFile(file.Id, false)
	}
	if deleteSource {
		go CleanUp(false)
	}
}

// DeleteFileSchedule schedules a file for deletion after a specified delay and optionally deletes its source.
// Returns true if scheduling is successful, false otherwise.
func DeleteFileSchedule(fileId string, delayMs int, deleteSource bool) bool {
	if fileId == "" {
		return false
	}
	file, ok := database.GetMetaDataById(fileId)
	if !ok {
		return false
	}
	if file.IsDisposed() {
		purgeFile(file.Id, "removed by owner")
		return true
	}
	deletionTime := time.Now().Add(time.Duration(delayMs) * time.Millisecond).Unix()
	file.PendingDeletion = deletionTime
	database.SaveMetaData(file)
	// Explicit parameter to avoid accidental changes
	go func(id string, timestamp int64) {
		time.Sleep(time.Duration(delayMs) * time.Millisecond)
		// A new models.File needs to be assigned to avoid a racy mutation
		retrievedFile, exists := database.GetMetaDataById(id)
		if !exists {
			return
		}
		// To prevent race conditions, it is checked if the deletion time is the same time that was originally set
		if retrievedFile.PendingDeletion == timestamp {
			DeleteFile(id, deleteSource)
		}
	}(fileId, deletionTime)
	return true
}

// CancelPendingFileDeletion removes the pending deletion flag for a file identified by the given ID.
//
// Refuses once the record is disposed of, whatever the reason - IsDisposed(), not
// Status() == StatusDeleted: Status reports "expired" or "downloaded" rather than "deleted" for
// two of the three disposal reasons (see models.File.Status), and there is nothing to restore for
// any of them either way, since the content is already gone. Also refuses once the record's
// pending deletion timer has already elapsed and CleanUp simply has not caught up to it yet -
// without that second check, a restore requested in the gap between the timer elapsing and the
// next sweep would succeed and then be disposed of anyway moments later, silently undoing the
// restore.
//
// Returns false if the file was not found, or if it can no longer be restored.
func CancelPendingFileDeletion(fileId string) (models.File, bool) {
	if fileId == "" {
		return models.File{}, false
	}
	file, ok := database.GetMetaDataById(fileId)
	if !ok {
		return models.File{}, false
	}
	if file.IsDisposed() || file.Status(DownloadAccessOf(file), time.Now().Unix()) == models.StatusDeleted {
		return models.File{}, false
	}
	file.PendingDeletion = 0
	database.SaveMetaData(file)
	return file, true
}

// MigratePlaintextFileNames converts any file name that a version predating encrypted file names
// left in plaintext, and records the count in the log. Runs once the master key is available:
// at startup for the encryption levels that load their key there, and immediately after a
// successful unseal for the Input levels, which have no key before that point.
//
// A sealed instance is skipped rather than made to fail, so that this stays safe to call
// unconditionally from startup - the unseal path picks the work up later in that case.
func MigratePlaintextFileNames() {
	if encryption.IsSealed() {
		return
	}
	migrated := database.MigratePlaintextFileNames()
	if migrated > 0 {
		logging.LogFileNameMigration(migrated)
	}
}
