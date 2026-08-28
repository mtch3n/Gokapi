package errorHandling

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/forceu/gokapi/internal/helper"
)

var tokens = make(map[string]DisplayedError)
var mutex sync.RWMutex
var cleanupOnce sync.Once

const ttl = 5 * time.Minute

// maxTokens bounds the tokens map so that a flood of requests hitting redirectToError (e.g.
// unauthenticated bad-id probes against /pubapi/*, none of which previously went through any
// rate limiter) cannot grow it without bound between the hourly cleanup passes.
const maxTokens = 10000

const WidthDefault = "20rem"
const WidthWide = "30rem"
const WidthVeryWide = "65%"

const (
	TypeFileNotFound = iota
	TypeInvalidFileRequest
	TypeE2ECipher
	TypeOAuthNotAuthorised
	TypeOAuthNonGeneric
)

type DisplayedError struct {
	Title                string
	Message              string
	OAuthProviderMessage string
	CardWidth            string
	ErrorId              int
	IsGeneric            bool
	expiry               int64
}

func (d DisplayedError) IsExpired() bool {
	return d.expiry < time.Now().Unix()
}

func RedirectToErrorPage(w http.ResponseWriter, r *http.Request, errorTitle, errorMessage, cardWidth string) {
	result := DisplayedError{
		Title:     errorTitle,
		Message:   errorMessage,
		expiry:    time.Now().Add(ttl).Unix(),
		CardWidth: cardWidth,
	}
	redirectToError(w, r, result)
}

func RedirectGenericErrorPage(w http.ResponseWriter, r *http.Request, genericType int) {
	var cardWidth string
	switch genericType {
	case TypeFileNotFound:
		cardWidth = WidthDefault
	case TypeInvalidFileRequest:
		cardWidth = WidthWide
	case TypeE2ECipher:
		cardWidth = WidthVeryWide
	case TypeOAuthNotAuthorised:
		cardWidth = WidthWide
	default:
		redirectToError(w, r, DisplayedError{
			Title:     "Unknown error",
			Message:   "Gokapi cannot display this error (error code " + strconv.Itoa(genericType) + ")",
			CardWidth: WidthWide,
			expiry:    time.Now().Add(ttl).Unix(),
		})
		return
	}

	result := DisplayedError{
		expiry:    time.Now().Add(ttl).Unix(),
		ErrorId:   genericType,
		IsGeneric: true,
		CardWidth: cardWidth,
	}
	redirectToError(w, r, result)
}

func RedirectToOAuthErrorPage(w http.ResponseWriter, r *http.Request, errorMessage string, err error) {
	if r.URL.Query().Get("error") == "access_denied" {
		result := DisplayedError{
			Title:     "Access denied",
			Message:   "The request was denied by the user or authentication provider.",
			expiry:    time.Now().Add(ttl).Unix(),
			ErrorId:   TypeOAuthNonGeneric,
			IsGeneric: false,
		}
		redirectToError(w, r, result)
		return
	}
	if err != nil {
		errorMessage = errorMessage + " " + err.Error()
	}
	result := DisplayedError{
		Title:                r.URL.Query().Get("error"),
		Message:              errorMessage,
		OAuthProviderMessage: r.URL.Query().Get("error_description"),
		expiry:               time.Now().Add(ttl).Unix(),
		ErrorId:              TypeOAuthNonGeneric,
		IsGeneric:            false,
	}
	redirectToError(w, r, result)
}

func redirectToError(w http.ResponseWriter, r *http.Request, displayedError DisplayedError) {
	token := helper.GenerateRandomString(30)
	mutex.Lock()
	if len(tokens) >= maxTokens {
		// Bound memory under a flood of bad-id probes: opportunistically drop expired entries
		// first, and if that is not enough, evict one arbitrary entry rather than let the map
		// grow without bound. Go's map iteration order is randomised, so this is not a
		// predictable or targetable eviction order.
		for id, existing := range tokens {
			if existing.IsExpired() {
				delete(tokens, id)
			}
		}
		if len(tokens) >= maxTokens {
			for id := range tokens {
				delete(tokens, id)
				break
			}
		}
	}
	tokens[token] = displayedError
	mutex.Unlock()

	cleanupOnce.Do(func() {
		go cleanup(true)
	})
	http.Redirect(w, r, "./error?e="+token, http.StatusTemporaryRedirect)
}

func Get(r *http.Request) DisplayedError {
	mutex.RLock()
	defer mutex.RUnlock()
	if !r.URL.Query().Has("e") {
		return DisplayedError{
			IsGeneric: true,
			ErrorId:   TypeFileNotFound,
			CardWidth: WidthDefault,
		}
	}
	displayedError, ok := tokens[r.URL.Query().Get("e")]
	if !ok {
		return DisplayedError{
			Title:     "Unknown error ID",
			Message:   "Unfortunately, an error occurred and the error message could not be displayed.",
			CardWidth: WidthDefault,
		}
	}
	return displayedError
}

func cleanup(periodic bool) {
	mutex.Lock()
	for id, token := range tokens {
		if token.IsExpired() {
			delete(tokens, id)
		}
	}
	mutex.Unlock()
	if periodic {
		// Matches ttl rather than the previous hourly interval: an hour-long window between
		// cleanups let a lot more expired entries accumulate under sustained bad-id probing than
		// the 5-minute ttl implies.
		time.Sleep(ttl)
		go cleanup(true)
	}

}
