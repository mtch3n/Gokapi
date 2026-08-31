// Package avatar caches the profile picture an OIDC provider advertises for a user, so the app
// can show it without the browser ever contacting the identity provider. That indirection is the
// whole point: the production CSP is img-src 'self' data:, and a page that may display a
// filename must make no third-party request, so an <img> pointing at googleusercontent.com is
// both blocked and unwanted. The bytes are fetched once server-side and served from this origin.
package avatar

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/png"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/forceu/gokapi/internal/configuration"

	// Registers the decoders for the formats an OIDC provider realistically serves. Decoding and
	// re-encoding, rather than storing the response body as-is, is what guarantees the cached file
	// is an image at all and that its content type is ours rather than the remote server's.
	_ "image/gif"
	_ "image/jpeg"
)

const (
	// maxDownloadBytes caps the response body. Profile pictures are a few tens of kB; anything
	// far beyond that is a misconfiguration or an attempt to fill the data directory.
	maxDownloadBytes = 1 << 20
	// maxDimension rejects decompression bombs before any pixel buffer is allocated.
	maxDimension = 2048
	// refreshAfter is how long a cached picture is trusted before the next login re-fetches it.
	// Without this a user who changes their provider photo would keep the old one forever.
	refreshAfter   = 7 * 24 * time.Hour
	requestTimeout = 10 * time.Second
)

var errBlockedAddress = errors.New("avatar: refusing to connect to a non-public address")

// client only ever talks to the identity provider's public picture host. The dial control hook
// rejects loopback, private and link-local addresses so a hostile or compromised provider cannot
// use this fetch as a probe of anything behind the server.
var client = &http.Client{
	Timeout: requestTimeout,
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: requestTimeout,
			Control: func(_, address string, _ syscall.RawConn) error {
				host, _, err := net.SplitHostPort(address)
				if err != nil {
					return err
				}
				ip := net.ParseIP(host)
				if ip == nil {
					return errBlockedAddress
				}
				if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
					ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
					return errBlockedAddress
				}
				return nil
			},
		}).DialContext,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return errors.New("avatar: too many redirects")
		}
		if req.URL.Scheme != "https" {
			return errors.New("avatar: refusing to follow a redirect away from https")
		}
		return nil
	},
}

// directory is where cached pictures live. It is created lazily, on the first successful fetch.
func directory() string {
	return filepath.Join(configuration.Get().DataDir, "avatars")
}

// Path returns the cached picture for a user and whether one exists.
func Path(userId int) (string, bool) {
	path := filepath.Join(directory(), fmt.Sprintf("%d.png", userId))
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return "", false
	}
	return path, true
}

// Delete removes a user's cached picture. Missing is not an error.
func Delete(userId int) {
	path := filepath.Join(directory(), fmt.Sprintf("%d.png", userId))
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		log.Printf("avatar: could not remove cached picture for user %d: %v", userId, err)
	}
}

// StoreAsync caches the picture at pictureUrl for the given user, in the background. It is called
// on the OIDC login path, where the user is waiting on a redirect: a slow or unreachable picture
// host must never delay or fail the login, so every outcome here is logged rather than returned.
func StoreAsync(userId int, pictureUrl string) {
	if pictureUrl == "" {
		return
	}
	if !needsRefresh(userId) {
		return
	}
	go func() {
		err := store(userId, pictureUrl)
		if err != nil {
			log.Printf("avatar: could not cache the profile picture for user %d: %v", userId, err)
		}
	}()
}

// needsRefresh reports whether there is no cached picture yet, or the cached one is old enough
// that the provider may have a newer one.
func needsRefresh(userId int) bool {
	path, ok := Path(userId)
	if !ok {
		return true
	}
	info, err := os.Stat(path)
	if err != nil {
		return true
	}
	return time.Since(info.ModTime()) > refreshAfter
}

func store(userId int, pictureUrl string) error {
	parsed, err := url.Parse(pictureUrl)
	if err != nil {
		return err
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return fmt.Errorf("picture url is not https: %s", parsed.Scheme)
	}

	response, err := client.Get(pictureUrl)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("picture host answered %s", response.Status)
	}

	// One extra byte, so a body that is exactly at the cap is still recognised as over it.
	body, err := io.ReadAll(io.LimitReader(response.Body, maxDownloadBytes+1))
	if err != nil {
		return err
	}
	if len(body) > maxDownloadBytes {
		return fmt.Errorf("picture is larger than %d bytes", maxDownloadBytes)
	}

	encoded, err := toPng(body)
	if err != nil {
		return err
	}
	return writeAtomically(userId, encoded)
}

// toPng validates the downloaded bytes really are a decodable image of a sane size, and returns
// them re-encoded as PNG so the cache holds exactly one format.
func toPng(body []byte) ([]byte, error) {
	config, _, err := image.DecodeConfig(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if config.Width > maxDimension || config.Height > maxDimension {
		return nil, fmt.Errorf("picture is %dx%d, larger than the %dpx limit", config.Width, config.Height, maxDimension)
	}
	decoded, _, err := image.Decode(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	err = png.Encode(&out, decoded)
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// writeAtomically writes through a temporary file in the same directory, so a request that
// arrives mid-write never reads a half-written picture.
func writeAtomically(userId int, content []byte) error {
	dir := directory()
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, "avatar")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	_, err = temp.Write(content)
	if err != nil {
		temp.Close()
		os.Remove(tempName)
		return err
	}
	err = temp.Close()
	if err != nil {
		os.Remove(tempName)
		return err
	}
	err = os.Rename(tempName, filepath.Join(dir, fmt.Sprintf("%d.png", userId)))
	if err != nil {
		os.Remove(tempName)
		return err
	}
	return nil
}
