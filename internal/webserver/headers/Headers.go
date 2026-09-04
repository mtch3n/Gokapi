package headers

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/forceu/gokapi/internal/models"
)

// Write sets headers to either display the file inline or to force download, the content type,
// and - for encrypted files - stable resume validators (see the comment below).
func Write(file models.File, w http.ResponseWriter, forceDownload, serveDecrypted bool) {
	encodedName := strings.NewReplacer("+", "%2B").Replace(url.PathEscape(file.Name))
	disposition := "attachment"
	if !forceDownload {
		disposition = "inline"
		w.Header().Set("Content-Security-Policy", "sandbox")
	}

	w.Header().Set("Content-Disposition", disposition+"; filename=\""+file.Name+"\"; filename*=UTF-8''"+encodedName)
	if !file.RequiresClientDecryption() || serveDecrypted {
		w.Header().Set("Content-Type", file.ContentType)
		w.Header().Set("Content-Length", strconv.FormatInt(file.SizeBytes, 10))
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}

	// Accept-Ranges is deliberately not set here. http.ServeContent sets it itself for every
	// caller that hands it a seekable reader - which, since storage.ServeFile now wraps
	// encrypted local files in a SectionReader over encryption.DecryptReaderAt, is every local
	// download, encrypted or not. The only callers left that don't go through ServeContent are
	// the S3 proxy paths (internal/storage/filesystem/s3filesystem/aws), which stream with
	// io.Copy and cannot honour a Range request at all - so they must not advertise one either.
	if file.Encryption.IsEncrypted {
		// UploadDate and SHA1 are fixed at upload time and never change afterwards, unlike
		// time.Now(): a resuming client's If-Range carries whichever validator this handler
		// returned on its first response, and that can only match a later request if the
		// response is stable. SHA1 is the stronger validator - this storage is content-addressed
		// by it - and is set as a strong Etag so http.ServeContent's If-Range/If-None-Match
		// handling can match it directly; UploadDate is also set as Last-Modified as a fallback
		// for the rarer client that only sends a date in If-Range.
		w.Header().Set("Last-Modified", time.Unix(file.UploadDate, 0).UTC().Format(http.TimeFormat))
		w.Header().Set("Etag", `"`+file.SHA1+`"`)
	}
}
