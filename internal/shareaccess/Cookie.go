package shareaccess

import (
	"net/http"
	"sync"
	"time"

	"github.com/forceu/gokapi/internal/configuration/database"
	"github.com/forceu/gokapi/internal/helper"
	"github.com/forceu/gokapi/internal/logging"
	"github.com/forceu/gokapi/internal/models"
)

// The access cookie is held in memory only, never written to disk. This
// mirrors internal/webserver/authentication/downloadPasswordToken, which does
// the same for passcode-protected downloads.
//
// Why a cookie at all, when the mailed link already carries a token: without
// one, the token rides in the query string of every subsequent request, and
// reverse proxies log the full request URI by default. A long-lived credential
// would then sit in plain text in access logs, which get rotated, shipped and
// read. Exchanging it once for a cookie, then redirecting to a clean URL,
// keeps the token out of the log after the first hit, out of the browser's
// history, and off the screen during a screen share.
//
// Why memory rather than a table: authorisation is re-checked against the
// grant on every request, so blocking a recipient takes effect immediately
// either way. The only cost of a restart is that the recipient follows the
// mailed link again, which still works because that link is reusable.
type accessCookie struct {
	RecipientId  int
	ResourceType int
	ResourceId   string
	Expiry       int64
}

var (
	cookieMutex  sync.RWMutex
	cookieStore  = make(map[string]accessCookie)
	cleanupOnce  sync.Once
	cookieLength = 60
)

// CookieName returns the cookie used for one resource. Scoping the name to the
// resource means a recipient holding several shares keeps one cookie per
// share, matching the rule that a link authorises exactly what it was issued
// for.
func CookieName(resourceType int, resourceId string) string {
	prefix := "sa"
	switch resourceType {
	case models.ShareResourceBundle:
		prefix = "sb"
	case models.ShareResourceFileRequest:
		prefix = "sr"
	}
	return prefix + "_" + resourceId
}

// WriteCookie exchanges a validated token for a cookie and sets it on the
// response.
func WriteCookie(w http.ResponseWriter, r *http.Request, resourceType int, resourceId string, recipientId int) {
	value := helper.GenerateRandomString(cookieLength)
	expiry := time.Now().Add(models.ShareCookieValiditySeconds * time.Second)

	cookieMutex.Lock()
	cookieStore[value] = accessCookie{
		RecipientId:  recipientId,
		ResourceType: resourceType,
		ResourceId:   resourceId,
		Expiry:       expiry.Unix(),
	}
	cookieMutex.Unlock()

	cleanupOnce.Do(func() { go cleanupLoop() })

	http.SetCookie(w, &http.Cookie{
		Name:     CookieName(resourceType, resourceId),
		Value:    value,
		Expires:  expiry,
		HttpOnly: true,
		// Secure is derived from how the request arrived rather than hardcoded,
		// so a plain-HTTP development instance still works while a real
		// deployment behind TLS gets the flag.
		Secure:   isHttps(r),
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})
}

// ReadCookie returns the recipient authorised by the request's cookie for this
// resource, or false.
//
// It only establishes identity. The caller must still confirm the grant, so
// that revoking access does not wait for the cookie to expire.
func ReadCookie(r *http.Request, resourceType int, resourceId string) (int, bool) {
	cookie, err := r.Cookie(CookieName(resourceType, resourceId))
	if err != nil {
		return 0, false
	}
	cookieMutex.RLock()
	entry, ok := cookieStore[cookie.Value]
	cookieMutex.RUnlock()
	if !ok {
		return 0, false
	}
	if entry.Expiry < time.Now().Unix() {
		cookieMutex.Lock()
		delete(cookieStore, cookie.Value)
		cookieMutex.Unlock()
		return 0, false
	}
	// A cookie is bound to the resource it was issued for, so one obtained for
	// a file cannot be presented against a different one.
	if entry.ResourceType != resourceType || entry.ResourceId != resourceId {
		return 0, false
	}
	return entry.RecipientId, true
}

// TokenQueryParam is the query parameter carrying an access token. It is kept as a fallback
// only: the mailed link itself now carries the token in the URL fragment (see BuildAccessUrl),
// which is never sent to the server at all, so links mailed before that change - still valid for
// up to 30 days - and any other caller that lands here with the old query form both keep working.
const TokenQueryParam = "token"

// TokenHeader is the request header the SPA forwards the token in, since a fragment never
// reaches the server and has to be read out client-side. It mirrors the existing apikey header
// idiom used elsewhere on /pubapi/*.
const TokenHeader = "sharetoken"

// RecipientFor returns the recipient authorised for this resource by the
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
//
// It lives here rather than in package webserver because the guest upload endpoints in
// webserver/api need the exact same answer, and api cannot import webserver. There is one
// implementation of "is this caller currently entitled to this resource", and both the download
// paths and the chunk upload paths ask it here.
func RecipientFor(w http.ResponseWriter, r *http.Request, resourceType int, resourceId string) int {
	rawToken := r.Header.Get(TokenHeader)
	if rawToken == "" {
		rawToken = r.URL.Query().Get(TokenQueryParam)
	}
	if rawToken != "" {
		recipient, firstUse, err := ValidateToken(rawToken, resourceType, resourceId)
		if err == nil {
			if w != nil {
				WriteCookie(w, r, resourceType, resourceId, recipient.Id)
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
	recipientId, ok := ReadCookie(r, resourceType, resourceId)
	if !ok {
		return 0
	}
	if !database.HasShareGrant(resourceType, resourceId, recipientId) {
		return 0
	}
	return recipientId
}

func isHttps(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	// Behind a reverse proxy the connection to Gokapi is plain HTTP, so the
	// proxy's forwarded scheme is the only signal that the client used TLS.
	return r.Header.Get("X-Forwarded-Proto") == "https"
}

func cleanupLoop() {
	for {
		time.Sleep(time.Minute)
		now := time.Now().Unix()
		cookieMutex.Lock()
		for value, entry := range cookieStore {
			if entry.Expiry < now {
				delete(cookieStore, value)
			}
		}
		cookieMutex.Unlock()
	}
}

// resetCookieStoreForTesting empties the store between tests.
func resetCookieStoreForTesting() {
	cookieMutex.Lock()
	defer cookieMutex.Unlock()
	cookieStore = make(map[string]accessCookie)
}
