package webserver

import (
	"net/http"

	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/shareaccess"
)

// shareTokenParam is the query parameter carrying an access token, as built
// into the link mailed to a recipient.
const shareTokenParam = "token"

// recipientFor returns the recipient authorised for this resource by the
// current request, or 0.
//
// Two ways in are accepted, in this order:
//
//  1. A token in the query string, which is what the mailed link carries. On
//     success it is exchanged for a cookie so the token stops appearing in
//     later request URLs, and therefore in browser history and proxy access
//     logs.
//  2. A cookie from an earlier exchange.
//
// The grant is re-checked on every call, not trusted from the cookie, so
// removing a recipient or blocking them takes effect on their next request
// rather than when their cookie happens to expire.
func recipientFor(w http.ResponseWriter, r *http.Request, resourceType int, resourceId string) int {
	if rawToken := r.URL.Query().Get(shareTokenParam); rawToken != "" {
		recipient, err := shareaccess.ValidateToken(rawToken, resourceType, resourceId)
		if err == nil {
			if w != nil {
				shareaccess.WriteCookie(w, r, resourceType, resourceId, recipient.Id)
			}
			return recipient.Id
		}
		// A bad token falls through to the cookie rather than failing
		// outright: a recipient who already has a session should not be locked
		// out by clicking a link that has since been superseded by a resend.
	}
	recipientId, ok := shareaccess.ReadCookie(r, resourceType, resourceId)
	if !ok {
		return 0
	}
	if !database.HasShareGrant(resourceType, resourceId, recipientId) {
		return 0
	}
	return recipientId
}

// mayAccessShare reports whether the request may reach this resource at all.
//
// A resource with no recipients is unrestricted and keeps the behaviour it has
// always had: possession of the link, plus any passcode, is enough. A resource
// with recipients is reachable only by one of them.
func mayAccessShare(w http.ResponseWriter, r *http.Request, resourceType int, resourceId string) bool {
	if !database.IsShareRestricted(resourceType, resourceId) {
		return true
	}
	return recipientFor(w, r, resourceType, resourceId) != 0
}

// shareAccessMode reports which download flow applies, for a client to branch
// on. The server decides; a client never infers it from a combination of
// booleans.
func shareAccessMode(file models.File) string {
	return file.AccessMode(database.IsShareRestricted(models.ShareResourceFile, file.Id))
}

// consumeShareDownload records a download against the recipient's own
// allowance when the resource is restricted.
//
// Returns false when the allowance is exhausted, in which case the caller must
// not serve the file. For an unrestricted resource there is no per-recipient
// allowance and this is a no-op, leaving the existing per-file counter as the
// only limit.
func consumeShareDownload(r *http.Request, resourceType int, resourceId string) bool {
	if !database.IsShareRestricted(resourceType, resourceId) {
		return true
	}
	recipientId, ok := shareaccess.ReadCookie(r, resourceType, resourceId)
	if !ok {
		// Fall back to a token in the URL, for a client that downloads
		// straight from the mailed link without loading the page first.
		if rawToken := r.URL.Query().Get(shareTokenParam); rawToken != "" {
			recipient, err := shareaccess.ValidateToken(rawToken, resourceType, resourceId)
			if err != nil {
				return false
			}
			recipientId = recipient.Id
		} else {
			return false
		}
	}
	return shareaccess.ConsumeDownload(resourceType, resourceId, recipientId) == nil
}

// accessibleBundleMembers narrows a bundle's member list to the files the current
// requester may individually access.
//
// A bundle-level restriction is not the only restriction a member can carry: a file can
// also have been shared on its own, with its own recipient list, independently of any
// bundle it happens to sit in. Such a member must stay invisible to a bundle recipient who
// is not also on the file's own list - the bundle grant is not a substitute for the file's.
// For a member with no restriction of its own this is a no-op, matching mayAccessShare.
func accessibleBundleMembers(w http.ResponseWriter, r *http.Request, members []models.File) []models.File {
	result := make([]models.File, 0, len(members))
	for _, file := range members {
		if mayAccessShare(w, r, models.ShareResourceFile, file.Id) {
			result = append(result, file)
		}
	}
	return result
}
