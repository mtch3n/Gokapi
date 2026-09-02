package webserver

import (
	"net/http"

	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/logging"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/shareaccess"
)

// shareTokenParam is the query parameter carrying an access token. It is kept as a fallback
// only: the mailed link itself now carries the token in the URL fragment (see
// shareaccess.BuildAccessUrl), which is never sent to the server at all, so links mailed before
// that change - still valid for up to 30 days - and any other caller that lands here with the
// old query form both keep working.
const shareTokenParam = "token"

// shareTokenHeader is the request header the SPA forwards the token in, since a fragment never
// reaches the server and has to be read out client-side. It mirrors the existing apikey header
// idiom used elsewhere on /pubapi/*.
const shareTokenHeader = "sharetoken"

// recipientFor returns the recipient authorised for this resource by the
// current request, or 0.
//
// Three ways in are accepted, in this order:
//
//  1. A token in the sharetoken request header, which is how the SPA forwards the fragment
//     token it read out of the mailed link.
//  2. A token in the query string, kept as a fallback: links mailed before the fragment change
//     still carry it there, and a caller that downloads straight from the link (no JS, so no
//     header) has no other way to present it.
//  3. A cookie from an earlier exchange.
//
// On success from either token form it is exchanged for a cookie so it stops appearing in later
// requests, and therefore in browser history and proxy access logs.
//
// The grant is re-checked on every call, not trusted from the cookie, so
// removing a recipient or blocking them takes effect on their next request
// rather than when their cookie happens to expire.
func recipientFor(w http.ResponseWriter, r *http.Request, resourceType int, resourceId string) int {
	rawToken := r.Header.Get(shareTokenHeader)
	if rawToken == "" {
		rawToken = r.URL.Query().Get(shareTokenParam)
	}
	if rawToken != "" {
		recipient, firstUse, err := shareaccess.ValidateToken(rawToken, resourceType, resourceId)
		if err == nil {
			if w != nil {
				shareaccess.WriteCookie(w, r, resourceType, resourceId, recipient.Id)
			}
			if firstUse {
				logging.LogShareLinkRedeemed(resourceType, resourceId, recipient, r)
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
		// Fall back to a token in the URL query. Mailed links now carry the token in a
		// fragment the server never sees, but this fallback remains for pre-fragment mailed
		// links (?token= form, valid up to 30 days) presented directly to a download URL.
		if rawToken := r.URL.Query().Get(shareTokenParam); rawToken != "" {
			// firstUse is not raised here: this fallback only feeds the download-consuming
			// path, and recipientFor - which does raise share.link.redeemed - is always the
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
		// itself expired, the same gap recipientFor already closes for the
		// read-only access check.
		return false
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
