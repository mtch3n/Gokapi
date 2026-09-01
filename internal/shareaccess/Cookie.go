package shareaccess

import (
	"net/http"
	"sync"
	"time"

	"github.com/forceu/gokapi/internal/helper"
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
