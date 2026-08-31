// Package features computes the server's effective, client-facing capability set. It is the
// single place that decides which optional behaviours are actually available right now,
// combining configuration flags with runtime preconditions (e.g. whether the encryption master
// key is loaded) rather than echoing raw configuration back to a client. Keeping this logic out
// of the webserver/api and configuration packages keeps "is this feature usable" decoupled
// from both HTTP transport and raw settings storage.
package features

import (
	"github.com/forceu/gokapi/internal/configuration"
	"github.com/forceu/gokapi/internal/encryption"
)

// Features is a stable, extensible set of booleans describing which optional server
// capabilities are currently usable. New fields can be added here without breaking existing
// clients, since the JSON object is always keyed by name.
type Features struct {
	// StoreShareKeys is true only when both the operator has opted in (configuration.
	// StoreShareKeys) and the server can actually decrypt anything server-side right now (the
	// master key is loaded, see encryption.IsDecryptionAvailable). A server configured for
	// end-to-end encryption, or with no encryption key loaded, never holds a key capable of
	// decrypting a stored share password again, so the feature must report false regardless of
	// the flag.
	StoreShareKeys bool `json:"storeShareKeys"`
}

// Get returns the server's current effective feature set.
func Get() Features {
	return Features{
		StoreShareKeys: configuration.Get().StoreShareKeys && encryption.IsDecryptionAvailable(),
	}
}
