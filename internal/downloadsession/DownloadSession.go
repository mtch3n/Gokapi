// Package downloadsession mints and verifies the token that lets the party who spent a download
// keep retrying it while its window is open.
//
// The window belongs to whoever holds the token rather than to whoever holds the resource's link,
// which is the whole point: a spent link is dead for everyone, so a stranger cannot ride the
// window opened by someone else's broken transfer. The token is still a bearer credential and is
// deliberately not tied to the presenter - the recipient id it carries buys attribution in the
// audit log and revocation when that recipient's grant is withdrawn, not untransferability.
//
// Stateless by design. The server keeps no record of what it has issued, so there is nothing to
// revoke and nothing to migrate: the expiry travels inside the token and the signature is the
// only thing that has to be checked. What that costs is that a token cannot be withdrawn early -
// which is why it is scoped to one resource and dies with the window it was minted for.
package downloadsession

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/forceu/gokapi/internal/configuration"
)

// ParamName is the query parameter the token travels in. The download link carries it rather
// than a cookie: a cookie cannot reach an external download manager, and being able to hand a
// copied link to one is the case this exists to serve.
const ParamName = "session"

// tokenVersion is carried in the payload so a future format change can be rejected outright
// rather than misread. A token that does not name this version is refused.
const tokenVersion = 1

// minSignKeyLength is the shortest signing key this package will use. Both minting and verifying
// check it, so the two can never disagree about what counts as adequate.
const minSignKeyLength = 32

// payload is what the token asserts. It deliberately holds nothing about the file beyond the id
// already visible in the URL it travels in: no name, no content type, no key material, no nonce,
// no password hash. A token is a permission to retry one download, not a description of it, and
// it ends up in browser history and proxy logs where a description would not belong.
type payload struct {
	Version      int    `json:"v"`
	ResourceType int    `json:"t"`
	ResourceId   string `json:"id"`
	RecipientId  int    `json:"r"`
	ExpiresAt    int64  `json:"exp"`
}

// Claims is the decoded payload returned by Verify.
type Claims struct {
	Version      int
	ResourceType int
	ResourceId   string
	RecipientId  int
	ExpiresAt    int64
}

// Sign returns a token authorising retries of this resource until expiresAt, bound to the given
// recipientId. An empty string is returned if the signing key is too short, which would silently
// weaken every token.
func Sign(resourceType int, resourceId string, recipientId int, expiresAt int64) string {
	signKey := configuration.GetEnvironment().DownloadSessionSignKey
	if len(signKey) < minSignKeyLength {
		return ""
	}
	body, err := json.Marshal(payload{
		Version:      tokenVersion,
		ResourceType: resourceType,
		ResourceId:   resourceId,
		RecipientId:  recipientId,
		ExpiresAt:    expiresAt,
	})
	if err != nil {
		return ""
	}
	encoded := base64.RawURLEncoding.EncodeToString(body)
	return encoded + "." + base64.RawURLEncoding.EncodeToString(sign(encoded, signKey))
}

// Verify reports whether token authorises a retry of this exact resource at time now. It returns
// the decoded claims and a success flag. If verification fails, claims are zero-valued and the flag
// is false.
//
// The signature is checked before the payload is parsed, so a forged or corrupt token is never
// decoded. Every failure returns the same false: a caller cannot tell an expired token from a
// forged one from one minted for a different file, and does not need to.
func Verify(token string, resourceType int, resourceId string, now int64) (Claims, bool) {
	signKey := configuration.GetEnvironment().DownloadSessionSignKey
	if len(signKey) < minSignKeyLength {
		return Claims{}, false
	}
	encoded, signature, found := strings.Cut(token, ".")
	if !found {
		return Claims{}, false
	}
	expected, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return Claims{}, false
	}
	if !hmac.Equal(expected, sign(encoded, signKey)) {
		return Claims{}, false
	}
	body, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return Claims{}, false
	}
	var claims payload
	if json.Unmarshal(body, &claims) != nil {
		return Claims{}, false
	}
	if claims.Version != tokenVersion {
		return Claims{}, false
	}
	if claims.ResourceType != resourceType {
		return Claims{}, false
	}
	if claims.ResourceId != resourceId {
		return Claims{}, false
	}
	if claims.ExpiresAt <= now {
		return Claims{}, false
	}
	return Claims{
		Version:      claims.Version,
		ResourceType: claims.ResourceType,
		ResourceId:   claims.ResourceId,
		RecipientId:  claims.RecipientId,
		ExpiresAt:    claims.ExpiresAt,
	}, true
}

// sign is the MAC over the encoded payload using the provided key. The key length is checked by
// both callers rather than here: returning an empty MAC for a short key would make hmac.Equal
// accept a token whose signature is also empty, since two zero-length slices compare equal.
func sign(encoded string, key string) []byte {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(encoded))
	return mac.Sum(nil)
}
