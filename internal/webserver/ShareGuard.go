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
	_, ok := resolveShareAccess(w, r, resourceType, resourceId)
	return ok
}

// resolveShareAccess is mayAccessShare's full answer, for the callers that also need to know WHO
// the request resolved to rather than only whether it may proceed: attachRecipient needs the id
// for audit attribution, and so does the non-spending download authorisation below. Split out
// rather than having every such caller call shareaccess.RecipientFor a second time, which would
// mean resolving - and, on a fresh token, cookie-exchanging - the same identity twice per request.
//
// recipientId is 0 exactly when the resource is unrestricted; a restricted resource that refuses
// still reports the recipient it found, if any, so a caller that wants to log who was refused can.
func resolveShareAccess(w http.ResponseWriter, r *http.Request, resourceType int, resourceId string) (recipientId int, authorised bool) {
	if !database.IsShareRestricted(resourceType, resourceId) {
		return 0, true
	}
	recipientId = shareaccess.RecipientFor(w, r, resourceType, resourceId)
	if recipientId == 0 {
		return 0, false
	}
	if shareaccess.IsExhausted(resourceType, resourceId, recipientId, shareLeewayFor(resourceType, resourceId)) {
		return recipientId, false
	}
	return recipientId, true
}

// downloadAuthResult is what mayDownloadFile and mayDownloadBundle answer: not merely whether the
// caller may proceed, but enough for a caller to act on that verdict without asking any further
// question of its own.
type downloadAuthResult struct {
	// Authorised is true exactly when today's spending gates - shareaccess.ConsumeDownload
	// inline in serveFile (Webserver.go:1330) and consumeShareDownload (Webserver.go:1356 and
	// the four call sites in pubApiFolderZip) - would let this request through.
	Authorised bool
	// RecipientId is the recipient this request resolved to: the file's own, if the file itself
	// is identity-restricted, otherwise its governing bundle's. Zero for a wholly unrestricted
	// resource, or when nobody was resolved before the refusal (an unknown or missing recipient
	// cookie/token). Present so a caller can attach it for audit attribution - see
	// attachRecipient - without resolving the same identity a second time.
	RecipientId int
	// BundleRecipientId is the recipient resolved against the file's GOVERNING BUNDLE
	// specifically, set whenever that bundle is identity-restricted - including when the file
	// itself is ALSO restricted, in which case RecipientId above is the file's own and this is
	// the separate identity the bundle's own allowance must be spent against. Zero when the
	// bundle is unrestricted. Exists so a caller spending the bundle's allowance can pass this
	// straight to consumeShareDownload rather than re-deriving it - see that function's doc
	// comment for why re-deriving it a narrower way is exactly the bug this avoids.
	BundleRecipientId int
	// RequiresPassword is true only when the single reason this call refused is a missing or
	// no-longer-valid passcode cookie (a file's own p<id> cookie, or a bundle's b<id> cookie) -
	// never set together with Authorised, and never set for a recipient-restriction refusal. A
	// caller needs this distinguished from every other refusal because the two answers differ:
	// "ask again for the password" versus "there is nothing here for you".
	RequiresPassword bool
	// DenialReason is a short, human-readable explanation of a refusal, for a caller writing an
	// audit denial entry - never set together with Authorised. Kept as free text rather than an
	// enum because its only consumer is logging.LogDownloadDenied's reason string, which is
	// itself free text; a caller that needs to branch on WHY a request was refused should branch
	// on Authorised/RequiresPassword/RecipientId instead, not parse this.
	DenialReason string
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

// consumeShareDownload records a download against recipientId's own allowance when the resource
// is restricted.
//
// recipientId is the identity the caller's OWN authorisation step already resolved - via
// shareaccess.RecipientFor, directly or through resolveShareAccess/mayDownloadFile/
// mayDownloadBundle - never re-derived here from a narrower source. This function used to read a
// cookie itself, with a bare query-token fallback that did not understand the sharetoken HEADER
// RecipientFor accepts - which let a caller authorised via a header-carried token be refused
// right here at the spend, because the two steps disagreed about what counted as identity.
// RecipientFor's own grant check (HasShareGrant, on both its cookie and its token path) is what
// makes the explicit re-check this function used to do redundant now that every caller is
// required to have gone through it first.
//
// Returns false when the allowance is already exhausted, in which case the caller must not serve
// the file, or when the resource is restricted but no recipientId was resolved. A request
// arriving inside the window a previous spend opened used to be let through here for free; that
// free ride is gone (see the leeway-session-token plan, D24), superseded by the download session
// token, which is stronger. For an unrestricted resource there is no per-recipient allowance and
// this is a no-op, leaving the existing per-file counter as the only limit. leeway is still the
// window length the caller resolves for the resource being served (see storage.LeewayFor), in
// seconds, passed through to shareaccess.ConsumeDownload for its disposal-side bookkeeping, but it
// no longer decides whether this call succeeds.
func consumeShareDownload(resourceType int, resourceId string, recipientId int, leeway int64) bool {
	if !database.IsShareRestricted(resourceType, resourceId) {
		return true
	}
	if recipientId == 0 {
		return false
	}
	return shareaccess.ConsumeDownload(resourceType, resourceId, recipientId, leeway) == nil
}

// recipientGrantStillValid re-checks, at the moment a download session token is served, that the
// recipient it names still has a live grant on this resource and has not been blocked since the
// token was minted (see the leeway-session-token plan, D23). A stateless bearer token carries no
// revocation list of its own; this is what makes blocking or removing a recipient take effect on
// the very next tokened request rather than waiting out the rest of the window.
func recipientGrantStillValid(resourceType int, resourceId string, recipientId int) bool {
	if !database.HasShareGrant(resourceType, resourceId, recipientId) {
		return false
	}
	recipient, ok := database.GetShareRecipient(recipientId)
	return ok && !recipient.IsBlocked
}

// accessibleBundleMembers narrows a bundle's member list to the files the current
// requester may individually access.
//
// A bundle-level restriction is not the only restriction a member can carry: a file can
// also have been shared on its own, with its own recipient list, independently of any
// bundle it happens to sit in. Such a member must stay invisible to a bundle recipient who
// is not also on the file's own list - the bundle grant is not a substitute for the file's.
// For a member with no restriction of its own this is a no-op, matching mayAccessShare.
//
// exemptRecipientId is the folder token holder's own recipient id on the tokened leg (0
// otherwise - see pubApiFolderZip's call site, D28). D24 made a recipient's own exhaustion
// refuse immediately rather than after a window closes, which is correct everywhere except
// here: a folder token proves this identity already spent (or was exempted from spending) for
// the life of the window, so re-deriving a fresh cookie-based identity for THIS member and
// then refusing it for being exhausted would silently drop a member the mint already paid for.
// Checked directly against HasShareGrant instead of going through mayAccessShare/RecipientFor,
// since the token - not a cookie this request may not even carry for this specific file - is
// the identity here. Every OTHER recipient's own grant on a member is unaffected and still
// filtered by mayAccessShare's real exhaustion check, exactly as before.
func accessibleBundleMembers(w http.ResponseWriter, r *http.Request, members []models.File, exemptRecipientId int) []models.File {
	result := make([]models.File, 0, len(members))
	for _, file := range members {
		if exemptRecipientId != 0 && database.IsShareRestricted(models.ShareResourceFile, file.Id) {
			if database.HasShareGrant(models.ShareResourceFile, file.Id, exemptRecipientId) {
				result = append(result, file)
			}
			continue
		}
		if mayAccessShare(w, r, models.ShareResourceFile, file.Id) {
			result = append(result, file)
		}
	}
	return result
}

// mayDownloadFile is the non-spending twin of every gate serveFile runs before it is willing to
// spend a download and write the first byte (see the leeway-session-token plan, D27 and §2.8:
// "a HEAD request must run every authorisation gate and then answer with headers only, spending
// nothing" - something serveFile's OLD inline gates could not do, because on that shape the
// gates ARE the spends). serveFile's tokenless leg now calls this directly for its own
// authorisation, rather than duplicating the logic inline; only the two spends that follow
// (shareaccess.ConsumeDownload and consumeShareDownload) still live in serveFile itself.
//
// It answers the identical question serveFile's body answers between resolving the file (via
// storage.GetFile, which already covers existence, expiry and the AGGREGATE allowance - see
// storage.IsExpiredFile - and is itself a pure read, so it is not repeated here) and calling
// storage.ServeFile: may THIS caller, specifically, have it. That is three gates, run in a fixed
// order because the order decides which refusal reason wins when more than one gate would refuse:
//
//  1. A restricted governing bundle - existence of a resolvable recipient only; deferred to step
//     3 below for the exhaustion half, matching consumeShareDownload's position in serveFile.
//  2. The file's own restriction, superseding a passcode entirely - shareaccess.ConsumeDownload's
//     non-spending twin, resolveShareAccess, in one step because serveFile spends the very
//     recipient id it just resolved (RecipientId, below) rather than re-deriving it - or, when
//     the file carries no restriction of its own, its passcode cookie (isValidPwCookie).
//  3. The governing bundle's allowance, actually exhausted or not - deferred to here because
//     serveFile's own consumeShareDownload(bundle) call sits after the passcode branch, so a
//     missing passcode answers "needs a password" even when the bundle grant behind it happens to
//     already be spent.
//
// A cookie IS still written here when the caller presents a fresh access token - exactly as
// mayAccessShare already does via shareaccess.RecipientFor - because exchanging a token for a
// cookie is bookkeeping for the caller's OWN later requests, not a spend against the resource: it
// touches neither a DownloadsRemaining nor a DownloadsUsed column. Nothing else here writes
// anything.
//
// BundleRecipientId is returned alongside RecipientId specifically so serveFile's later spend of
// the bundle's own allowance (consumeShareDownload) can be given the identity resolved HERE,
// through RecipientFor, rather than re-deriving it a narrower way. It used to: consumeShareDownload
// read a cookie directly, with a bare query-token fallback that did not understand the sharetoken
// header RecipientFor accepts, so a caller authorised by a header-carried token could reach this
// function's Authorised:true and then be refused at the spend for a reason invisible to it. Fixed
// by making the spend take the id rather than resolve one of its own; see consumeShareDownload's
// doc comment.
func mayDownloadFile(w http.ResponseWriter, r *http.Request, file models.File) downloadAuthResult {
	bundleRestricted := file.BundleId != "" && database.IsShareRestricted(models.ShareResourceBundle, file.BundleId)
	var bundleRecipientId int
	if bundleRestricted {
		bundleRecipientId = shareaccess.RecipientFor(w, r, models.ShareResourceBundle, file.BundleId)
		if bundleRecipientId == 0 {
			return downloadAuthResult{DenialReason: "no valid recipient access for the file's restricted bundle"}
		}
	}

	recipientId := bundleRecipientId
	if database.IsShareRestricted(models.ShareResourceFile, file.Id) {
		fileRecipientId, ok := resolveShareAccess(w, r, models.ShareResourceFile, file.Id)
		if !ok {
			// resolveShareAccess still reports the recipient it found, if any, so this
			// distinguishes "nobody" (an unknown or missing recipient cookie/token) from "this
			// recipient, but their allowance is gone" - the same distinction serveFile's old
			// inline gates drew between refusing before a spend and having the spend itself fail.
			reason := "no valid recipient access for a restricted file"
			if fileRecipientId != 0 {
				reason = "recipient download allowance exhausted"
			}
			return downloadAuthResult{RecipientId: fileRecipientId, BundleRecipientId: bundleRecipientId, DenialReason: reason}
		}
		recipientId = fileRecipientId
	} else if file.PasswordHash != "" && !isValidPwCookie(r, file) {
		return downloadAuthResult{RecipientId: bundleRecipientId, BundleRecipientId: bundleRecipientId, RequiresPassword: true}
	}

	if bundleRestricted && shareaccess.IsExhausted(models.ShareResourceBundle, file.BundleId, bundleRecipientId,
		shareLeewayFor(models.ShareResourceBundle, file.BundleId)) {
		return downloadAuthResult{RecipientId: bundleRecipientId, BundleRecipientId: bundleRecipientId,
			DenialReason: "bundle download allowance exhausted"}
	}
	return downloadAuthResult{Authorised: true, RecipientId: recipientId, BundleRecipientId: bundleRecipientId}
}

// mayDownloadBundle is mayDownloadFile's folder twin: the non-spending answer to every gate
// pubApiFolderZip runs before it spends a member's, the bundle recipients', or the folder's own
// visit allowance (consumeShareDownload and consumeBundleDownload, in both branches of
// pubApiFolderZip). Like mayDownloadFile it answers only the identity questions -
// storage.IsAvailableBundle/IsAvailableBundleInWindow already cover the folder's own existence,
// expiry and aggregate allowance as a pure read, and stay a separate call the caller makes
// alongside this one, not something repeated here.
//
// Order matches pubApiFolderZip's tokenless leg exactly, because it decides which refusal wins:
//
//  1. Recipient restriction - existence only; deferred to step 3 below for the exhaustion half.
//  2. The folder's own password (isValidPwCookieBundle, non-spending already).
//  3. The recipient's allowance, actually exhausted or not - deferred to here because a missing
//     password must answer "needs a password" even when the grant behind it is already spent.
//
// This does not cover a member's OWN restriction, independent of the bundle's - that is
// mayDownloadFile's question, asked once per member by accessibleBundleMembers, and answering it
// here too would just be the same call twice. Nor does it apply to a tokened request at all:
// pubApiFolderZip resolves identity from the token's own claims on that leg instead, since the
// token - not a fresh cookie/header resolution - IS the authorisation by then.
func mayDownloadBundle(w http.ResponseWriter, r *http.Request, bundle models.FileBundle) downloadAuthResult {
	restricted := database.IsShareRestricted(models.ShareResourceBundle, bundle.Id)
	var recipientId int
	if restricted {
		recipientId = shareaccess.RecipientFor(w, r, models.ShareResourceBundle, bundle.Id)
		if recipientId == 0 {
			return downloadAuthResult{DenialReason: "no valid recipient access for the folder"}
		}
	}

	if bundle.PasswordHash != "" && !isValidPwCookieBundle(r, bundle) {
		return downloadAuthResult{RecipientId: recipientId, RequiresPassword: true}
	}

	if restricted && shareaccess.IsExhausted(models.ShareResourceBundle, bundle.Id, recipientId,
		shareLeewayFor(models.ShareResourceBundle, bundle.Id)) {
		return downloadAuthResult{RecipientId: recipientId, DenialReason: "recipient download allowance exhausted"}
	}
	return downloadAuthResult{Authorised: true, RecipientId: recipientId}
}
