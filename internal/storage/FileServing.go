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
	for _, file := range files {
		if !IsExpiredFile(file, timeNow) {
			result[file.UserId] = result[file.UserId] + 1
		}
	}
	return result
}

// NewFileFromChunk creates a new file in the system after a chunk upload has fully completed. If a file with the same sha1 hash
// already exists, it is deduplicated. This function gathers information about the file, creates an ID and saves
// it into the global configuration.
//
// Serialised end-to-end on chunkId via apimutex (see H3): without this, N parallel completion
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

	// removeEncryptedTemp cleans up tempFileEnc on every error path below once it exists (see
	// H3): previously, once os.CreateTemp had succeeded, any later error - a failed encrypt, a
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
// deliberate and visible to the person choosing the key: a typed password is more likely to be
// one they use elsewhere, and this keeps it recoverable to anyone who can both reach
// /api/files/{id}/sharekey and unseal the instance. The upload form says so at the point the key
// is chosen. To restore the previous "generated keys only" rule, gate this on the caller's
// GeneratedPassword signal again, which is still carried end to end.
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

// GetSharePassword returns the decrypted, auto-generated share password stored for file, if
// any. The bool return is false whenever the plaintext cannot or must not be returned - the
// feature toggle is off, no key was ever stored for this file (e.g. it had a manual password,
// or was uploaded before the feature was enabled), or the server master key is unavailable -
// all collapsed into the same signal so a caller cannot distinguish "off" from "no master key"
// from "nothing stored" (see the /api/files/{id}/sharekey endpoint, which must not become an
// oracle for any of those).
func GetSharePassword(file models.File) (string, bool) {
	if !configuration.Get().StoreShareKeys || len(file.EncryptedSharePassword) == 0 {
		return "", false
	}
	plaintext, err := encryption.DecryptString(file.EncryptedSharePassword)
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
		if !file.UnlimitedDownloads {
			file.DownloadsRemaining = database.GetDownloadsRemaining(file.Id)
		}
		if IsExpiredFile(file, time.Now().Unix()) {
			apimutex.Unlock(apimutex.TypeMetaData, file.Id)
			return false
		}
	}
	if increaseCounter {
		if !file.UnlimitedDownloads {
			if !database.IncreaseDownloadCount(file.Id, true) {
				// The atomic, floored decrement lost the race (or found the allowance already exhausted) -
				// this caller must not serve the file, regardless of what the pre-fetched file struct says.
				apimutex.Unlock(apimutex.TypeMetaData, file.Id)
				return false
			}
		} else {
			database.IncreaseDownloadCount(file.Id, false)
		}
		file.DownloadsRemaining = file.DownloadsRemaining - 1
		file.DownloadCount = file.DownloadCount + 1
		go sse.PublishDownloadCount(file)
	}
	apimutex.Unlock(apimutex.TypeMetaData, file.Id)

	// Fail closed: the audit record for this download is committed (fsync'd) to durable local
	// storage before any bytes are served below, and the request is refused if that write
	// fails - so a crash between the two can only over-log (an audit entry for a download that
	// did not fully complete), never serve content with no record of it. See
	// internal/logging/AuditLog.go for the chain design.
	//
	// Note the increaseCounter block above (W2's territory) already ran: if increaseCounter was
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

// CleanUp removes expired files from the config and from the filesystem if they are not referenced by other files anymore
// Will be called periodically or after a file has been manually deleted in the admin view.
// If the parameter periodic is true, this function is recursive and calls itself every hour.
func CleanUp(periodic bool) {
	downloadstatus.Clean()
	timeNow := time.Now().Unix()
	wasItemDeleted := false
	for key, element := range database.GetAllMetadata() {
		fileExists := FileExists(element, configuration.Get().DataDir)
		reason := ""
		switch {
		case !fileExists:
			reason = "stored object missing"
		case isExpiredFileWithoutDownload(element, timeNow):
			reason = "expired"
		case isPendingToBeDeleted(element, timeNow):
			reason = "pending deletion timer elapsed"
		}
		if reason != "" {
			deleteFile := true
			for _, secondLoopElement := range database.GetAllMetadata() {
				if (element.Id != secondLoopElement.Id) && (element.SHA1 == secondLoopElement.SHA1) {
					deleteFile = false
					break
				}
			}
			if deleteFile && fileExists {
				deleteSource(element, configuration.Get().DataDir)
			}
			if element.HotlinkId != "" {
				database.DeleteHotlink(element.HotlinkId)
			}
			database.DeleteMetaData(key)
			logging.LogFileExpired(element, reason)
			wasItemDeleted = true
		}
	}
	if wasItemDeleted {
		CleanUp(false)
	}
	cleanOldTempFiles()
	cleanHotlinks()
	purgeHotlinksIfDisabled()
	cleanInvalidApiKeys()
	cleanInvalidFileRequests()
	cleanInvalidBundles()
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

// cleanInvalidBundles removes bundles that have zero non-pending members and are older than 24 hours
func cleanInvalidBundles() {
	bundles := database.GetAllFileBundles()
	files := database.GetAllMetadata()

	for _, bundle := range bundles {
		if !bundle.IsOlderThanGracePeriod() {
			continue
		}
		hasValidMember := false
		for _, file := range files {
			if file.BundleId == bundle.Id && !file.IsPendingForDeletion() {
				hasValidMember = true
				break
			}
		}
		if !hasValidMember {
			database.DeleteFileBundle(bundle)
		}
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

// isPendingToBeDeleted returns true if a pending deletion has to be executed
func isPendingToBeDeleted(file models.File, timeNow int64) bool {
	if !file.IsPendingForDeletion() {
		return false
	}
	return file.PendingDeletion < timeNow
}

// IsExpiredFile returns true if the file is expired, either due to download count
// or if the provided timestamp is after the expiry timestamp
func IsExpiredFile(file models.File, timeNow int64) bool {
	return (file.ExpireAt < timeNow && !file.UnlimitedTime) ||
		(file.DownloadsRemaining < 1 && !file.UnlimitedDownloads)
}

// isExpiredFileWithoutDownload returns true if there is no active download for an expired file
func isExpiredFileWithoutDownload(file models.File, timeNow int64) bool {
	if downloadstatus.IsCurrentlyDownloading(file) {
		return false
	}
	return IsExpiredFile(file, timeNow)
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

// DeleteFile is called when an admin requests deletion of a file.
// Returns true if the file was deleted or false if ID did not exist.
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
	file.ExpireAt = 0
	file.UnlimitedTime = false
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
// Returns false if the file was not found
func CancelPendingFileDeletion(fileId string) (models.File, bool) {
	if fileId == "" {
		return models.File{}, false
	}
	file, ok := database.GetMetaDataById(fileId)
	if !ok {
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
