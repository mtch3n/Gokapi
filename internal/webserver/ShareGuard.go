package webserver

import (
	"net/http"

	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/logging"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/shareaccess"
	"github.com/forceu/gokapi/internal/storage"
)

// attachRecipient looks up recipientId and, if it names a real recipient, returns a shallow
// copy of r with it attached via logging.WithRecipient - the sibling of WithActor - so that a
// download or upload served through r afterwards is attributed to that recipient instead of
// being recorded as anonymous. recipientId == 0 (an unrestricted resource) and an id that no
// longer resolves are both a no-op, returning r unchanged. Must be called before the resource is
// served or the request is refused, so every audit entry written from then on - including a
// denial for an exhausted allowance - carries the identity.
func attachRecipient(r *http.Request, recipientId int) *http.Request {
	if recipientId == 0 {
		return r
	}
	recipient, ok := database.GetShareRecipient(recipientId)
	if !ok {
		return r
	}
	return logging.WithRecipient(r, recipient)
}

// mayAccessShare reports whether the request may reach this resource at all.
//
// A resource with no recipients is unrestricted and keeps the behaviour it has
// always had: possession of the link, plus any passcode, is enough. A resource
// with recipients is reachable only by one of them, and only while that one
// still has an allowance left.
//
// Spending the last of it ends this recipient's access outright rather than
// only refusing them the download: they were given a number of collections and
// they have taken them all, so there is nothing left for them to be shown. It
// ends nobody else's - every other recipient keeps their own budget, and the
// resource itself lives until the last of them is finished or it expires.
func mayAccessShare(w http.ResponseWriter, r *http.Request, resourceType int, resourceId string) bool {
	if !database.IsShareRestricted(resourceType, resourceId) {
		return true
	}
	recipientId := shareaccess.RecipientFor(w, r, resourceType, resourceId)
	if recipientId == 0 {
		return false
	}
	return !shareaccess.IsExhausted(resourceType, resourceId, recipientId,
		shareLeewayFor(resourceType, resourceId))
}

// shareLeewayFor returns how long a download window stays open for this
// resource, so that "is this recipient finished with it" is asked with the same
// window the download itself is metered by rather than a second one. Only a
// secret differs - it has no window at all, see storage.LeewayFor - and a
// folder or a file request is always the configured leeway.
func shareLeewayFor(resourceType int, resourceId string) int64 {
	if resourceType == models.ShareResourceFile {
		if file, ok := database.GetMetaDataById(resourceId); ok {
			return int64(storage.LeewayFor(file).Seconds())
		}
	}
	return int64(storage.DownloadLeeway().Seconds())
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
// Returns false when the allowance is exhausted and no download window is open,
// in which case the caller must not serve the file. For an unrestricted resource
// there is no per-recipient allowance and this is a no-op, leaving the existing
// per-file counter as the only limit. leeway is the window length the caller
// resolved for the resource being served (see storage.LeewayFor), in seconds.
func consumeShareDownload(r *http.Request, resourceType int, resourceId string, leeway int64) bool {
	if !database.IsShareRestricted(resourceType, resourceId) {
		return true
	}
	recipientId, ok := shareaccess.ReadCookie(r, resourceType, resourceId)
	if !ok {
		// Fall back to a token in the URL query. Mailed links now carry the token in a
		// fragment the server never sees, but this fallback remains for pre-fragment mailed
		// links (?token= form, valid up to 30 days) presented directly to a download URL.
		if rawToken := r.URL.Query().Get(shareaccess.TokenQueryParam); rawToken != "" {
			// firstUse is not raised here: this fallback only feeds the download-consuming
			// path, and shareaccess.RecipientFor - which does raise share.link.redeemed - is
			// always the
			// first call to validate a token for a given request.
			recipient, _, err := shareaccess.ValidateToken(rawToken, resourceType, resourceId)
			if err != nil {
				return false
			}
			recipientId = recipient.Id
		} else {
			return false
		}
	} else if !database.HasShareGrant(resourceType, resourceId, recipientId) {
		// Unlike a token, a cookie carries no grant check of its own - ReadCookie
		// only proves the cookie is genuine, not that the grant behind it still
		// exists. Without this, revoking a recipient mid-cookie-lifetime would
		// not take effect on this download-consuming path until the cookie
		// itself expired, the same gap RecipientFor already closes for the
		// read-only access check.
		return false
	}
	return shareaccess.ConsumeDownload(resourceType, resourceId, recipientId, leeway) == nil
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
