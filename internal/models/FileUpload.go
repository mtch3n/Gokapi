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
	// the uploader (see the SPA's accessMode: "generated" vs "manual"). Only ever used to gate
	// whether the password may be stored encrypted for later retrieval (see
	// configuration.StoreShareKeys) - a manual password must never be persisted this way.
	GeneratedPassword bool
	ExternalUrl       string
	FileRequestId     string
	BundleId          string
}
