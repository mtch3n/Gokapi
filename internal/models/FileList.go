package models

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jinzhu/copier"
)

// Access modes reported to a client so it knows which download flow to run.
// The server decides the mode; a client never infers it from a combination of
// booleans. Adding a mode is therefore a server-side change that old clients
// fail closed on, rather than one they silently misinterpret.
const (
	// AccessModePublic means anyone holding the link may download. No
	// recipients and no password.
	AccessModePublic = "public"
	// AccessModePasscode means anyone holding the link and the one-off
	// passcode may download. A password is set and there are no recipients.
	AccessModePasscode = "passcode"
	// AccessModeIdentity means only a signed-in user on the file's recipient
	// list may download.
	AccessModeIdentity = "identity"
)

// AccessMode returns which download flow applies to this file.
//
// hasRecipients is passed in rather than read from the file because the
// recipient list lives in its own table: keeping it out of models.File means
// there is no second copy of the ACL that can fall out of step with the grant
// rows.
//
// A recipient list takes precedence over a password. Delivering two secrets
// for one file is a worse experience and buys nothing once access is already
// bound to an identity.
func (f *File) AccessMode(hasRecipients bool) string {
	if hasRecipients {
		return AccessModeIdentity
	}
	if f.PasswordHash != "" {
		return AccessModePasscode
	}
	return AccessModePublic
}

// DisposalReason records why a file's content was deleted. Valid only once DisposedAt is set.
const (
	// DisposalReasonNone means the file has not been disposed of.
	DisposalReasonNone = iota
	// DisposalReasonExpired means the file's expiry timestamp passed.
	DisposalReasonExpired
	// DisposalReasonDownloaded means the file's download allowance was used up.
	DisposalReasonDownloaded
	// DisposalReasonDeleted means the owner deleted the file.
	DisposalReasonDeleted
)

// Status values reported to a client so it knows how to render a file. The server decides the
// status; a client never infers it from a combination of booleans, the same rule AccessMode
// above follows and for the same reason: adding a status is a server-side change that old
// clients fail closed on, rather than one they silently misinterpret.
const (
	// StatusActive means the file is live and can be downloaded.
	StatusActive = "active"
	// StatusPendingDeletion means the owner scheduled a deletion whose delay has not yet elapsed.
	StatusPendingDeletion = "pending_deletion"
	// StatusExpired means the file's content was disposed of because its expiry timestamp passed.
	StatusExpired = "expired"
	// StatusDownloaded means the file's content was disposed of because its download allowance
	// was used up.
	StatusDownloaded = "downloaded"
	// StatusDeleted means the file's content was disposed of because the owner deleted it, or an
	// owner-scheduled deletion has elapsed and is about to be.
	StatusDeleted = "deleted"
)

// IsDisposed returns true if the file's content has been deleted, leaving this row behind as
// history. A disposed row carries no credential material - see storage.CleanUp - and every
// public path must treat it exactly like a row that was deleted outright.
func (f *File) IsDisposed() bool {
	return f.DisposedAt != 0
}

// DownloadAccess is the resolved set of axes that decide whether a resource may still be
// downloaded, and when its content is disposed of. It exists so that the two questions a caller
// would otherwise have to answer for itself - "does this file's own allowance govern it, or its
// folder's" and "how long is its download window" - are decided once, where the value is
// resolved (see storage.DownloadAccessOf), rather than at every call site that has to know.
//
// Leeway is how long the window stays open, in seconds. A window opens when a request spends an
// allowance and closes Leeway later; while it is open the resource is not exhausted, however
// many further requests arrive.
type DownloadAccess struct {
	ExpireAt           int64
	UnlimitedTime      bool
	DownloadsRemaining int
	UnlimitedDownloads bool
	WindowOpenedAt     int64
	Leeway             int64
}

// IsExpired reports whether the expiry timestamp has passed.
func (a DownloadAccess) IsExpired(timeNow int64) bool {
	return a.ExpireAt < timeNow && !a.UnlimitedTime
}

// GrantAllowance bounds a recipient's own download budget by the resource's. The owner set the
// resource's limit and it is the ceiling: a share may narrow what the owner allowed, never widen
// it, and a grant of 0 - "no limit of my own", which is what the share dialog sends unless the
// owner types a number - resolves to the owner's limit rather than to no limit at all. The result
// is 0, meaning unlimited, only when the resource itself is unlimited and the grant sets no limit
// either.
//
// used is what this recipient has already taken. It is added back because the two counters move
// in opposite directions: DownloadsRemaining falls as the recipient spends the budget, so
// comparing the grant's cap against it directly would shrink the budget every time part of it was
// used, and a recipient granted five downloads on a five-download file would get three.
func (a DownloadAccess) GrantAllowance(granted, used int) int {
	if a.UnlimitedDownloads {
		return granted
	}
	resourceCap := a.DownloadsRemaining + used
	if granted == 0 || granted > resourceCap {
		return resourceCap
	}
	return granted
}

// IsExhausted reports whether the download allowance is spent and no window is open anymore.
// With a leeway of 0 this is exactly "no downloads remaining", the rule that applied before
// windows existed.
func (a DownloadAccess) IsExhausted(timeNow int64) bool {
	return a.DownloadsRemaining < 1 && !a.UnlimitedDownloads && a.WindowOpenedAt+a.Leeway <= timeNow
}

// DownloadAccess returns the axes governing this file itself. Only correct for a file that
// belongs to no bundle - a member is governed by its folder instead, which is what
// storage.DownloadAccessOf resolves.
func (f *File) DownloadAccess(leeway int64) DownloadAccess {
	return DownloadAccess{
		ExpireAt:           f.ExpireAt,
		UnlimitedTime:      f.UnlimitedTime,
		DownloadsRemaining: f.DownloadsRemaining,
		UnlimitedDownloads: f.UnlimitedDownloads,
		WindowOpenedAt:     f.WindowOpenedAt,
		Leeway:             leeway,
	}
}

// Status computes which of the Status* values applies to this file, given the current time.
//
// A record already marked disposed reports the reason it was disposed of. One that is not yet
// physically disposed but whose condition for disposal has already been met - a pending
// deletion whose delay elapsed, an expiry timestamp in the past, a download allowance run out -
// reports the same status it will carry once the next storage.CleanUp pass catches up to it.
// The alternative, reporting "active" until the sweep actually runs, would make the owner's view
// depend on cron timing rather than on the file's own state.
func (f *File) Status(access DownloadAccess, timeNow int64) string {
	if f.IsDisposed() {
		switch f.DisposalReason {
		case DisposalReasonExpired:
			return StatusExpired
		case DisposalReasonDownloaded:
			return StatusDownloaded
		default:
			return StatusDeleted
		}
	}
	if f.PendingDeletion != 0 {
		// <, matching storage.isPendingToBeDeleted exactly, for the same reason: this method's
		// own doc comment promises the same status CleanUp will land on, so the two must agree
		// at the boundary too - see that function's comment for why it is strict.
		if f.PendingDeletion < timeNow {
			return StatusDeleted
		}
		return StatusPendingDeletion
	}
	if access.IsExhausted(timeNow) {
		return StatusDownloaded
	}
	if access.IsExpired(timeNow) {
		return StatusExpired
	}
	return StatusActive
}

// File is a struct used for saving information about an uploaded file
type File struct {
	Id                 string         `json:"Id" redis:"Id"`                                 // The internal ID of the file
	Name               string         `json:"Name" redis:"-"`                                // The filename, held in plaintext only in memory. Will be 'Encrypted file' for end-to-end encrypted files, and NameUnavailable while the instance is sealed
	Size               string         `json:"Size" redis:"Size"`                             // Filesize in a human-readable format
	SHA1               string         `json:"SHA1" redis:"SHA1"`                             // The hash of the file, used for deduplication. Cleared once the file is disposed
	PasswordHash       string         `json:"PasswordHash" redis:"PasswordHash"`             // The hash of the password (if the file is password-protected). Cleared once the file is disposed
	HotlinkId          string         `json:"HotlinkId" redis:"HotlinkId"`                   // If file is a picture file and can be hotlinked, this is the ID for the hotlink
	ContentType        string         `json:"ContentType" redis:"ContentType"`               // The MIME type for the file
	AwsBucket          string         `json:"AwsBucket" redis:"AwsBucket"`                   // If the file is stored in the cloud, this is the bucket that is being used
	UploadRequestId    string         `json:"FileRequestId" redis:"FileRequestId"`           // If the file belongs to a file request, this is the ID of the file request
	BundleId           string         `json:"BundleId" redis:"BundleId"`                     // If the file belongs to a bundle, this is the ID of the bundle
	ExpireAt           int64          `json:"ExpireAt" redis:"ExpireAt"`                     // UTC timestamp of file expiry
	PendingDeletion    int64          `json:"PendingDeletion" redis:"PendingDeletion"`       // UTC timestamp when the file will be deleted, if pending. Otherwise 0
	SizeBytes          int64          `json:"SizeBytes" redis:"SizeBytes"`                   // Filesize in bytes
	UploadDate         int64          `json:"UploadDate" redis:"UploadDate"`                 // UTC timestamp of upload time
	WindowOpenedAt     int64          `json:"WindowOpenedAt" redis:"WindowOpenedAt"`         // UTC timestamp the most recent download window opened, 0 if never. Server-side only, never reported to a client
	DownloadsRemaining int            `json:"DownloadsRemaining" redis:"DownloadsRemaining"` // The remaining downloads for this file
	DownloadCount      int            `json:"DownloadCount" redis:"DownloadCount"`           // The number of times the file has been downloaded
	UserId             int            `json:"UserId" redis:"UserId"`                         // The user ID of the uploader
	Encryption         EncryptionInfo `json:"Encryption" redis:"-"`                          // If the file is encrypted, this stores all info for decrypting. Key/nonce cleared once the file is disposed
	UnlimitedDownloads bool           `json:"UnlimitedDownloads" redis:"UnlimitedDownloads"` // True if the uploader did not limit the downloads
	UnlimitedTime      bool           `json:"UnlimitedTime" redis:"UnlimitedTime"`           // True if the uploader did not limit the time
	// DisposedAt is the UTC timestamp the file's content was deleted, leaving this row behind as
	// history. Zero means the content is still present. See Status/IsDisposed - nothing reads this
	// directly to decide whether a record is live; the point of that method is that no caller ever
	// has to.
	DisposedAt int64 `json:"DisposedAt" redis:"DisposedAt"`
	// DisposalReason records why the content was disposed of, valid only once DisposedAt is set.
	// See the DisposalReason* constants.
	DisposalReason          int    `json:"DisposalReason" redis:"DisposalReason"`
	InternalRedisEncryption []byte `redis:"EncryptionRedis"` // This field is an internal field, used to store the EncryptionInfo in a Redis Hashmap
	// NameEncryptedRaw carries the exact bytes stored for the name (format-prefixed ciphertext or
	// plaintext, see encryption.EncryptFileName/DecryptFileName), alongside the decrypted Name
	// above. Every provider's read path (GetAllMetadata/GetMetaDataById) populates this regardless
	// of whether Name could be decrypted, so a caller that saves this File back unchanged - most
	// importantly database.Migrate, which runs before the master key is loaded (see
	// cmd/gokapi/Main.go) and therefore can never decrypt an encrypted name - can write the
	// original bytes back verbatim instead of re-encrypting a Name it does not have. For Redis
	// this also doubles as the wire field: the "NameEncrypted" tag is what SaveMetaData writes
	// into the hash.
	NameEncryptedRaw []byte `json:"-" redis:"NameEncrypted"`
	// EncryptedSharePassword holds the file's share password, encrypted with the server master
	// key (see encryption.EncryptString), so it can be retrieved later through
	// /api/files/{id}/sharekey. Populated whenever configuration.StoreShareKeys is enabled and
	// a password was set, for a typed password as much as a generated one - the owner can look
	// up any key they set, not only the ones this app minted. Excluded from JSON output like
	// other sensitive fields (see User.AuthProvider) - callers read the plaintext through the
	// dedicated endpoint instead.
	EncryptedSharePassword []byte `json:"-" redis:"EncryptedSharePassword"`
}

// FileApiOutput will be displayed for public outputs from the ID, hiding sensitive information
type FileApiOutput struct {
	Id                           string `json:"Id"`                           // The internal ID of the file
	Name                         string `json:"Name"`                         // The filename. Will be 'Encrypted file' for end-to-end encrypted files
	Size                         string `json:"Size"`                         // Filesize in a human-readable format
	HotlinkId                    string `json:"HotlinkId"`                    // If the file is a picture file and can be hotlinked, this is the ID for the hotlink
	ContentType                  string `json:"ContentType"`                  // The MIME type for the file
	ExpireAtString               string `json:"ExpireAtString"`               // Time expiry in a human-readable format in UTC
	UrlDownload                  string `json:"UrlDownload"`                  // The public download URL for the file
	UrlHotlink                   string `json:"UrlHotlink"`                   // The public hotlink URL for the file
	FileRequestId                string `json:"FileRequestId"`                // The ID of the file request
	BundleId                     string `json:"BundleId"`                     // The ID of the bundle
	UploadDate                   int64  `json:"UploadDate"`                   // UTC timestamp of upload time
	ExpireAt                     int64  `json:"ExpireAt"`                     // UTC timestamp of file expiry
	SizeBytes                    int64  `json:"SizeBytes"`                    // Filesize in bytes
	DownloadsRemaining           int    `json:"DownloadsRemaining"`           // The remaining downloads for this file
	DownloadCount                int    `json:"DownloadCount"`                // The number of times the file has been downloaded
	UnlimitedDownloads           bool   `json:"UnlimitedDownloads"`           // True if the uploader did not limit the downloads
	UnlimitedTime                bool   `json:"UnlimitedTime"`                // True if the uploader did not limit the time
	DisposedAt                   int64  `json:"DisposedAt"`                   // UTC timestamp the file's content was deleted, or 0 if not disposed
	RequiresClientSideDecryption bool   `json:"RequiresClientSideDecryption"` // True if the file has to be decrypted client-side
	IsEncrypted                  bool   `json:"IsEncrypted"`                  // True if the file is encrypted
	IsEndToEndEncrypted          bool   `json:"IsEndToEndEncrypted"`          // True if the file is end-to-end encrypted
	IsPasswordProtected          bool   `json:"IsPasswordProtected"`          // True if a password has to be entered before downloading the file
	IsSavedOnLocalStorage        bool   `json:"IsSavedOnLocalStorage"`        // True if the file does not use cloud storage
	Status                       string `json:"Status"`                       // One of the Status* constants: active, pending_deletion, expired, downloaded or deleted
	IsFileRequest                bool   `json:"IsFileRequest"`                // True if the file belongs to a file request
	UploaderId                   int    `json:"UploaderId"`                   // The user ID of the uploader
}

// NameUnavailable is reported in place of a file name that could not be decrypted, which happens
// while the instance is sealed and the master key therefore does not exist yet. It is deliberately
// not an empty string: a client showing a blank cell cannot tell "this file has no name" apart
// from "this name is withheld for now", and the second is the only one that ever actually occurs.
const NameUnavailable = "(sealed)"

// EncryptionInfo holds information about the encryption used on the file
type EncryptionInfo struct {
	IsEncrypted         bool   `json:"IsEncrypted" redis:"IsEncrypted"`
	IsEndToEndEncrypted bool   `json:"IsEndToEndEncrypted" redis:"IsEndToEndEncrypted"`
	DecryptionKey       []byte `json:"DecryptionKey" redis:"DecryptionKey"`
	Nonce               []byte `json:"Nonce" redis:"Nonce"`
}

// IsLocalStorage returns true if the file is not stored on a remote storage
func (f *File) IsLocalStorage() bool {
	return f.AwsBucket == ""
}

// IsPendingForDeletion returns true if the file is pending to be deleted
func (f *File) IsPendingForDeletion() bool {
	return f.PendingDeletion != 0
}

// ToFileApiOutput returns a JSON object without sensitive information
func (f *File) ToFileApiOutput(serverUrl string, useFilenameInUrl bool, access DownloadAccess) (FileApiOutput, error) {
	var result FileApiOutput
	err := copier.Copy(&result, &f)
	if err != nil {
		return FileApiOutput{}, err
	}
	// copier has already copied Name across; an empty one here means the row could not be
	// decrypted, so report that rather than an empty cell (see NameUnavailable). A real file can
	// never legitimately have an empty name - uploads reject one.
	if result.Name == "" {
		result.Name = NameUnavailable
	}
	result.IsFileRequest = f.UploadRequestId != ""
	result.IsPasswordProtected = f.PasswordHash != ""
	result.IsEncrypted = f.Encryption.IsEncrypted
	result.IsSavedOnLocalStorage = f.AwsBucket == ""
	if f.Encryption.IsEndToEndEncrypted || f.RequiresClientDecryption() {
		result.RequiresClientSideDecryption = true
	}
	result.IsEndToEndEncrypted = f.Encryption.IsEndToEndEncrypted
	// A file collected through a file request is never publicly shareable, so it gets
	// no download or hotlink URL. The owner still has to be identifiable though - the
	// collect view lists a request's files by uploader, and copier does not map
	// File.UserId onto the differently named UploaderId, so leaving this unset here
	// made every collected file look like it belonged to user 0.
	if !f.IsFileRequest() {
		result.UrlHotlink = getHotlinkUrl(result, serverUrl, useFilenameInUrl)
		result.UrlDownload = getDownloadUrl(result, serverUrl, useFilenameInUrl)
	}
	result.UploaderId = f.UserId
	result.Status = f.Status(access, time.Now().Unix())
	result.FileRequestId = f.UploadRequestId
	result.ExpireAtString = time.Unix(f.ExpireAt, 0).UTC().Format("2006-01-02 15:04:05")

	return result, nil
}

func getDownloadUrl(input FileApiOutput, serverUrl string, useFilename bool) string {
	if useFilename {
		return serverUrl + "d/" + input.Id + "/" + escapeFilename(input.Name)
	}
	return serverUrl + "d?id=" + input.Id
}

func getHotlinkUrl(input FileApiOutput, serverUrl string, useFilename bool) string {
	if input.RequiresClientSideDecryption || input.IsPasswordProtected {
		return ""
	}
	if input.HotlinkId != "" {
		return serverUrl + "h/" + input.HotlinkId
	}
	if useFilename {
		return serverUrl + "dh/" + input.Id + "/" + escapeFilename(input.Name)
	}
	return serverUrl + "downloadFile?id=" + input.Id
}

// escapeFilename does a regular url escape, but replaces spaces with underscores for better readability
func escapeFilename(filename string) string {
	return url.PathEscape(strings.Replace(filename, " ", "_", -1))
}

// ToJsonResult converts the file info to a json String used for returning a result for an upload
func (f *File) ToJsonResult(serverUrl string, includeFilename bool, access DownloadAccess) string {
	info, err := f.ToFileApiOutput(serverUrl, includeFilename, access)
	if err != nil {
		return errorAsJson(err)
	}

	byteOutput, err := json.Marshal(Result{
		Result:          "OK",
		IncludeFilename: includeFilename,
		FileInfo:        info,
	})
	if err != nil {
		return errorAsJson(err)
	}
	return string(byteOutput)
}

// RequiresClientDecryption checks if the file needs to be decrypted by the client
// (if remote storage or end-to-end encryption)
func (f *File) RequiresClientDecryption() bool {
	if !f.Encryption.IsEncrypted {
		return false
	}
	return !f.IsLocalStorage() || f.Encryption.IsEndToEndEncrypted
}

// IsFileRequest checks if the file is uploaded for an upload request
func (f *File) IsFileRequest() bool {
	return f.UploadRequestId != ""
}

// IsBundleMember reports whether f counts as a current member of the bundle identified by
// bundleId: matching BundleId, not pending for deletion, not yet disposed of, and not a
// file-request upload. This is the one place that decides what "belongs to a bundle" means -
// an owner's member count and size (FileBundle.Populate), the files a recipient is actually
// handed (bundleMembers in internal/webserver), and the folder-delete confirmation all read
// through it, so a member excluded on one of those paths can no longer be counted on another.
// A file request never sets BundleId today, so the IsFileRequest exclusion is currently a no-op
// in practice - it is kept here anyway so that if that ever changes, every caller starts
// excluding it, or including it, together rather than one at a time.
func (f *File) IsBundleMember(bundleId string) bool {
	return f.BundleId == bundleId && !f.IsPendingForDeletion() && !f.IsDisposed() && !f.IsFileRequest()
}

func errorAsJson(err error) string {
	fmt.Println(err)
	errOutput := struct {
		Result       string `json:"Result"`
		ErrorMessage string `json:"ErrorMessage"`
	}{Result: "error", ErrorMessage: err.Error()}
	result, err := json.Marshal(errOutput)
	if err != nil {
		return "{\"Result\":\"error\",\"ErrorMessage\":\"Unknown error\"}"
	}
	return string(result)
}

// Result is the struct used for the result after an upload
// swagger:model UploadResult
type Result struct {
	Result          string        `json:"Result"`
	FileInfo        FileApiOutput `json:"FileInfo"`
	IncludeFilename bool          `json:"IncludeFilename"`
}

// DownloadStatus contains current downloads, so they do not get removed during cleanup
type DownloadStatus struct {
	Id       string
	FileId   string
	ExpireAt int64
}
