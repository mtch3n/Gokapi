package models

// A share recipient is an external person who was named on a share. They are
// deliberately NOT a models.User and hold no row in the Users table.
//
// That separation is the whole security argument for this design. A recipient
// cannot mint an API token, reach the dashboard, or upload, not because each
// of those was individually forbidden, but because every one of those code
// paths takes a models.User and a recipient is not one. Modelling a recipient
// as a User with a reduced rank would instead mean enumerating every
// capability to subtract, where missing one is a hole.

// Resource types a grant or a login token can point at. A secret is stored as
// an ordinary file, so it needs no type of its own. Multiple files are shared
// by putting them in a bundle, which is what the interface calls a folder.
const (
	// ShareResourceFile is a single file, which includes text secrets.
	ShareResourceFile = 0
	// ShareResourceBundle is a folder of files.
	ShareResourceBundle = 1
	// ShareResourceFileRequest is a request asking the recipient to upload.
	ShareResourceFileRequest = 2
)

// IsValidShareResourceType reports whether the value names a known resource
// type. Used to reject a type that arrived from outside the process, so an
// unknown value fails closed rather than matching nothing and silently
// granting or denying the wrong thing.
func IsValidShareResourceType(resourceType int) bool {
	switch resourceType {
	case ShareResourceFile, ShareResourceBundle, ShareResourceFileRequest:
		return true
	default:
		return false
	}
}

// ShareRecipient is an external person who may be granted access to shares.
type ShareRecipient struct {
	Id int `json:"id" redis:"Id"`
	// Email is normalised to lower case before storage, so that address
	// comparison is exact and a recipient cannot be duplicated by casing.
	Email     string `json:"email" redis:"Email"`
	CreatedAt int64  `json:"createdAt" redis:"CreatedAt"`
	// LastLoginAt is zero until the recipient first redeems a login link.
	LastLoginAt int64 `json:"lastLoginAt" redis:"LastLoginAt"`
	// IsBlocked revokes access while preserving the grant rows. Deleting the
	// recipient instead would break the audit trail of who was ever given
	// what.
	IsBlocked bool `json:"isBlocked" redis:"IsBlocked"`
}

// ShareGrant records that a recipient may reach one specific resource.
type ShareGrant struct {
	ResourceType int    `json:"resourceType" redis:"ResourceType"`
	ResourceId   string `json:"resourceId" redis:"ResourceId"`
	RecipientId  int    `json:"recipientId" redis:"RecipientId"`
	GrantedAt    int64  `json:"grantedAt" redis:"GrantedAt"`
	// GrantedBy is the staff models.User.Id that created the grant. Required
	// for the audit question "who gave this person access", which the
	// anonymous share model could never answer.
	GrantedBy int `json:"grantedBy" redis:"GrantedBy"`
	// DownloadsUsed counts what this recipient has taken. The allowance is
	// per recipient rather than per resource, so five recipients each get
	// their own budget instead of racing for one shared pool. It is also what
	// makes the audit answer "who downloaded, how often" rather than only
	// "the file was downloaded nine times".
	DownloadsUsed int `json:"downloadsUsed" redis:"DownloadsUsed"`
	// DownloadsAllowed caps that budget. Zero means unlimited.
	DownloadsAllowed int `json:"downloadsAllowed" redis:"DownloadsAllowed"`
	// LastDownloadAt is zero until the recipient first downloads.
	LastDownloadAt int64 `json:"lastDownloadAt" redis:"LastDownloadAt"`
}

// IsExhausted reports whether this recipient is finished with the resource:
// their own allowance is spent and the download window that spending it opened
// has closed. leeway is how long that window stays open, in seconds, resolved
// by the caller for the resource in question (see storage.LeewayFor) exactly as
// shareaccess.ConsumeDownload takes it, so there is one rule and only the
// window's length varies.
//
// It is the recipient-level twin of DownloadAccess.IsExhausted and defers to it
// rather than restating the test, so that "may this recipient still see it" and
// "may this resource still be served" can never drift apart.
//
// Exhaustion is strictly per recipient and revokes only that recipient: they
// stop seeing the resource at all - in their inbox and in the public metadata
// alike - while every other recipient's budget, and the resource's own
// lifetime, are untouched. Enforcing a download still goes through the
// database, which applies the same test atomically; deciding here and acting
// later would let two concurrent requests both pass.
func (g ShareGrant) IsExhausted(timeNow, leeway int64) bool {
	access := DownloadAccess{
		DownloadsRemaining: g.DownloadsAllowed - g.DownloadsUsed,
		UnlimitedDownloads: g.DownloadsAllowed == 0,
		WindowOpenedAt:     g.LastDownloadAt,
		Leeway:             leeway,
	}
	return access.IsExhausted(timeNow)
}

// ShareLoginToken is the magic link mailed to one recipient for one resource.
//
// It is deliberately REUSABLE, not single use. Three reasons, all practical:
// the recipient may open it more than once, the per-recipient download
// allowance already presumes repeat visits, and mail security products such as
// Outlook Safe Links fetch every URL they see, which would burn a single-use
// link before the human ever clicked it.
//
// The link is therefore a bearer credential with the lifetime of the resource.
// Anyone holding it has access. Forwarding the mail forwards the access, which
// the project has accepted as the recipient's own choice.
//
// Only the SHA-256 of the token is stored, never the token itself, so a
// database disclosure cannot be replayed into access. The existing Sessions
// and ApiKeys tables still hold their secrets in plain text, and this
// table is deliberately not inheriting that debt.
type ShareLoginToken struct {
	TokenHash    string `redis:"TokenHash"`
	RecipientId  int    `redis:"RecipientId"`
	ResourceType int    `redis:"ResourceType"`
	ResourceId   string `redis:"ResourceId"`
	// CreatedAt drives the resend cooldown. A recipient whose first link went
	// missing must be able to ask for another, but an unthrottled resend
	// button is a mail-bomb aimed at whatever address the attacker names, so
	// the interval between issues is enforced from this value.
	CreatedAt int64 `redis:"CreatedAt"`
	ExpiresAt int64 `redis:"ExpiresAt"`
	// FirstUsedAt records the first redemption, for audit only. It is not a
	// gate: the link stays valid afterwards.
	FirstUsedAt int64 `redis:"FirstUsedAt"`
	// IsRevoked retires this link without deleting the row, so that reissuing
	// a link can invalidate the previous one and the audit trail survives.
	IsRevoked   bool   `redis:"IsRevoked"`
	RequestedIp string `redis:"RequestedIp"`
}

// There is deliberately no ShareSession table. Once a link has been followed,
// the token is exchanged for a short-lived cookie held in memory, exactly as
// downloadPasswordToken already does for passcode-protected downloads. A
// database-backed session would buy nothing: authorisation is re-checked
// against the grant on every request, so blocking a recipient takes effect
// immediately either way, and a cookie lost to a restart costs the recipient
// one more click on a link that still works.

// ShareLinkCooldownSeconds is the minimum interval between issuing two login
// links for the same recipient and resource. Short enough that a recipient who
// genuinely lost the first mail is not left waiting, long enough that the
// resend button cannot be used to flood an inbox.
const ShareLinkCooldownSeconds = 60

// ShareLinkMaxValiditySeconds caps how long a link may live when the resource
// itself has no expiry. A link is normally given the resource's own expiry, so
// it cannot outlive what it points at; this only bounds the unlimited case.
const ShareLinkMaxValiditySeconds = 30 * 24 * 60 * 60

// ShareCookieValiditySeconds is how long the exchanged cookie lasts before the
// recipient has to follow the mailed link again.
const ShareCookieValiditySeconds = 2 * 60 * 60
