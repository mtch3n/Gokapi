package models

// UploadParameters is used to set parameters for a new upload
type UploadParameters struct {
	UserId              int
	AllowedDownloads    int
	Expiry              int
	MaxMemory           int
	ExpiryTimestamp     int64
	RealSize            int64
	UnlimitedDownload   bool
	UnlimitedTime       bool
	IsEndToEndEncrypted bool
	Password            string
	// GeneratedPassword signals that Password was generated client-side rather than typed by
	// the uploader (see the SPA's accessMode: "generated" vs "manual"). Informational only: it
	// gates nothing, since storage.EncryptSharePassword stores a typed password on the same
	// terms as a generated one.
	GeneratedPassword bool
	ExternalUrl       string
	FileRequestId     string
	BundleId          string
}
