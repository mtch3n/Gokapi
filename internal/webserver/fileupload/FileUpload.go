package fileupload

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/encryption"
	"github.com/forceu/gokapi/internal/environment"
	"github.com/forceu/gokapi/internal/logging"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/storage"
	"github.com/forceu/gokapi/internal/storage/chunking"
	"github.com/forceu/gokapi/internal/storage/chunking/chunkreservation"
	"github.com/forceu/gokapi/internal/webserver/errorHandling/errorcodes"
)

const minChunkSize = 5 * 1024 * 1024
const minChunkSizeLowMaxChunk = 1 * 1024 * 1024

// ProcessCompleteFile processes a file upload request
// This is only used when a complete file is uploaded through the API with /files/add
// Normally a file is created from a chunk
func ProcessCompleteFile(w http.ResponseWriter, r *http.Request, userId, maxMemory int) error {
	err := r.ParseMultipartForm(int64(maxMemory) * 1024 * 1024)
	if err != nil {
		return err
	}
	defer r.MultipartForm.RemoveAll()
	config, err := parseConfig(r.Form)
	if err != nil {
		return err
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		return err
	}

	config.FileRequestId = ""
	result, err := storage.NewFile(file, header, userId, config)
	defer file.Close()
	if err != nil {
		return err
	}
	user, _ := database.GetUser(userId)
	logging.LogUpload(result, user, models.FileRequest{})
	_, _ = io.WriteString(w, result.ToJsonResult(config.ExternalUrl, configuration.Get().IncludeFilename))
	return nil
}

func isChunkMinChunkSize(r *http.Request, offset, fileSize int64) bool {
	minReqChunkSize := minChunkSize
	if configuration.Get().ChunkSize < 5 {
		minReqChunkSize = minChunkSizeLowMaxChunk
	}
	if r.ContentLength >= int64(minReqChunkSize) {
		return true
	}
	if r.ContentLength >= (fileSize - offset) {
		return true
	}
	return false
}

// ProcessNewChunk processes a file chunk upload request
func ProcessNewChunk(w http.ResponseWriter, r *http.Request, isApiCall bool, filerequestId string, maxFileSize int64) (int, error) {
	err := r.ParseMultipartForm(int64(configuration.Get().MaxMemory) * 1024 * 1024)
	if err != nil {
		return errorcodes.CannotParse, err
	}
	defer r.MultipartForm.RemoveAll()
	chunkInfo, err := chunking.ParseChunkInfo(r, isApiCall)
	if err != nil {
		return errorcodes.InvalidUserInput, err
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		return errorcodes.InvalidUserInput, err
	}

	if !isChunkMinChunkSize(r, chunkInfo.Offset, chunkInfo.TotalFilesizeBytes) {
		return errorcodes.ChunkTooSmall, storage.ErrorChunkTooSmall
	}
	if chunkInfo.TotalFilesizeBytes > maxFileSize || chunkInfo.Offset > maxFileSize {
		return errorcodes.FileTooLarge, storage.ErrorFileTooLarge
	}

	if filerequestId != "" {
		if !chunkreservation.SetUploading(filerequestId, chunkInfo.UUID) {
			return errorcodes.InvalidChunkReservation, errors.New("chunk reservation has expired or was not requested")
		}
	}

	err = chunking.NewChunk(file, header, chunkInfo, maxFileSize)
	defer file.Close()
	if err != nil {
		return errorcodes.CannotAllocateFile, err
	}
	_, _ = io.WriteString(w, "{\"result\":\"OK\"}")
	return 0, nil
}

// ParseFileHeader parses the parameters for CompleteChunk()
// This is done as two operations, as CompleteChunk can be blocking too long
// for an HTTP request, by calling this function first, r can be closed afterwards
func ParseFileHeader(r *http.Request) (string, chunking.FileHeader, models.UploadParameters, error) {
	err := r.ParseForm()
	if err != nil {
		return "", chunking.FileHeader{}, models.UploadParameters{}, err
	}
	chunkId := r.PostForm.Get("chunkid")
	config, err := parseConfig(r.Form)
	if err != nil {
		return "", chunking.FileHeader{}, models.UploadParameters{}, err
	}
	header, err := chunking.ParseFileHeader(r)
	if err != nil {
		return "", chunking.FileHeader{}, models.UploadParameters{}, err
	}
	return chunkId, header, config, nil
}

// CompleteChunk processes a file after all the chunks have been completed
// The parameters can be generated with  ParseFileHeader()
func CompleteChunk(chunkId string, header chunking.FileHeader, userId int, config models.UploadParameters) (models.File, error) {
	return storage.NewFileFromChunk(chunkId, header, userId, config)
}

// ErrE2ENotConfigured is returned by CreateUploadConfig when a caller asserts
// end-to-end encryption but the server is not configured for it. The server,
// not a client-supplied flag, is authoritative on whether a file is E2E
// encrypted: trusting the caller here would mislabel the file and corrupt how
// it is later served (see file.Encryption.IsEndToEndEncrypted / F2).
var ErrE2ENotConfigured = errors.New("end-to-end encryption is not enabled on this server")

// CreateUploadConfig populates a new models.UploadParameters struct.
// It returns ErrE2ENotConfigured if isEnd2End is set while the server's
// encryption level is not encryption.EndToEndEncryption.
func CreateUploadConfig(allowedDownloads, expiryDays int, password string, unlimitedTime, unlimitedDownload, isEnd2End bool, realSize int64, fileRequestId string) (models.UploadParameters, error) {
	settings := configuration.Get()
	if isEnd2End && settings.Encryption.Level != encryption.EndToEndEncryption {
		return models.UploadParameters{}, ErrE2ENotConfigured
	}
	expiryDays, unlimitedTime = applyMaxExpiry(expiryDays, unlimitedTime)
	return models.UploadParameters{
		AllowedDownloads:    allowedDownloads,
		Expiry:              expiryDays,
		ExpiryTimestamp:     time.Now().Add(time.Duration(expiryDays) * time.Hour * 24).Unix(),
		Password:            password,
		ExternalUrl:         settings.ServerUrl,
		MaxMemory:           settings.MaxMemory,
		UnlimitedTime:       unlimitedTime,
		UnlimitedDownload:   unlimitedDownload,
		IsEndToEndEncrypted: isEnd2End,
		RealSize:            realSize,
		FileRequestId:       fileRequestId,
	}, nil
}

func parseConfig(values formOrHeader) (models.UploadParameters, error) {
	fileRequestId := values.Get("fileRequestId")
	if fileRequestId != "" {
		return CreateUploadConfig(0, 0, "",
			true, true, false, 0, fileRequestId)
	}
	allowedDownloads := values.Get("allowedDownloads")
	expiryDays := values.Get("expiryDays")
	password := values.Get("password")
	allowedDownloadsInt, err := strconv.Atoi(allowedDownloads)
	if err != nil {
		allowedDownloadsInt = 1
	}
	expiryDaysInt, err := strconv.Atoi(expiryDays)
	if err != nil {
		expiryDaysInt = 14
	}

	unlimitedDownload := values.Get("isUnlimitedDownload") == "true"
	unlimitedTime := values.Get("isUnlimitedTime") == "true"

	if allowedDownloadsInt == 0 {
		unlimitedDownload = true
	}
	if expiryDaysInt == 0 {
		unlimitedTime = true
	}

	var isEnd2End bool
	var realSize int64
	if values.Get("isE2E") == "true" {
		isEnd2End = true
		realSizeStr := values.Get("realSize")
		realSize, err = strconv.ParseInt(realSizeStr, 10, 64)
		if err != nil {
			return models.UploadParameters{}, err
		}
	}
	return CreateUploadConfig(allowedDownloadsInt, expiryDaysInt, password, unlimitedTime, unlimitedDownload, isEnd2End, realSize, "")
}

type formOrHeader interface {
	Get(key string) string
}

// applyMaxExpiry clamps an upload's lifetime to GOKAPI_MAX_EXPIRY_DAYS.
//
// Every upload path funnels through CreateUploadConfig, so enforcing here covers
// the web form, the API and file requests alike. File requests matter most: they
// are created with unlimitedTime set, so without this a file uploaded by an
// external party would never expire.
//
// A value of 0 keeps the upstream behaviour of allowing permanent files.
func applyMaxExpiry(expiryDays int, unlimitedTime bool) (int, bool) {
	maxExpiryDays := environment.New().MaxExpiryDays
	if maxExpiryDays < 1 {
		return expiryDays, unlimitedTime
	}
	if unlimitedTime || expiryDays < 1 || expiryDays > maxExpiryDays {
		return maxExpiryDays, false
	}
	return expiryDays, false
}

// ClampExpiryTimestamp applies GOKAPI_MAX_EXPIRY_DAYS to an absolute expiry timestamp.
//
// CreateUploadConfig covers every path that creates a file, but the edit API sets an
// expiry directly on existing metadata rather than going through an upload config, so
// without this an authorised editor could hand a file an unlimited lifetime or an
// arbitrarily distant expiry and defeat the retention policy.
//
// A maximum of 0 keeps the upstream behaviour of permitting permanent files.
func ClampExpiryTimestamp(expiryTimestamp int64, unlimitedTime bool) (int64, bool) {
	maxExpiryDays := environment.New().MaxExpiryDays
	if maxExpiryDays < 1 {
		return expiryTimestamp, unlimitedTime
	}
	latest := time.Now().Add(time.Duration(maxExpiryDays) * time.Hour * 24).Unix()
	if unlimitedTime || expiryTimestamp <= 0 || expiryTimestamp > latest {
		return latest, false
	}
	return expiryTimestamp, false
}
