package helper

/**
Generates / annotates strings
*/

import (
	cryptorand "crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

// Returns securely generated random bytes.
func generateRandomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = cryptorand.Read(b)
	return b
}

// GenerateRandomString returns a URL-safe, base64 encoded securely generated random string.
func GenerateRandomString(length int) string {
	b := generateRandomBytes(length + 10)
	result := cleanRandomString(base64.URLEncoding.EncodeToString(b))
	if len(result) < length {
		return GenerateRandomString(length)
	}
	return result[:length]
}

// passwordSpecialChars is the pool GenerateRandomPassword draws its guaranteed special
// character from. Deliberately narrow: a generated password is usually copied through a
// mail client, a URL or a terminal, and these survive all three without quoting.
const passwordSpecialChars = "-_.!@#$%*+="

// GenerateRandomPassword returns a securely generated random password of the given length
// that is guaranteed to contain a lowercase letter, an uppercase letter, a digit and a
// special character, so that it satisfies configuration.ValidatePasswordComplexity.
//
// GenerateRandomString cannot be used on its own for a password: it strips everything
// outside [a-zA-Z0-9], so its output never contains the special character the policy
// requires, and on a short length it can happen to contain no digit or no uppercase
// letter either. Handing an administrator a generated password that the server would
// reject if they typed it back is the failure this avoids.
func GenerateRandomPassword(length int) string {
	if length < 4 {
		length = 4
	}
	password := []byte(GenerateRandomString(length))
	// Four distinct positions, so seeding one class cannot overwrite another.
	positions := randomPositions(length, 4)
	password[positions[0]] = randomCharFrom("abcdefghijklmnopqrstuvwxyz")
	password[positions[1]] = randomCharFrom("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	password[positions[2]] = randomCharFrom("0123456789")
	password[positions[3]] = randomCharFrom(passwordSpecialChars)
	return string(password)
}

// randomCharFrom returns one uniformly chosen byte from pool.
func randomCharFrom(pool string) byte {
	index, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(len(pool))))
	if err != nil {
		panic(err)
	}
	return pool[index.Int64()]
}

// randomPositions returns count distinct indices below length, by shuffling the full range
// and taking the first count. Drawing at random and retrying on a collision would work too,
// but a partial Fisher-Yates has no retry loop to reason about.
func randomPositions(length, count int) []int {
	indices := make([]int, length)
	for i := range indices {
		indices[i] = i
	}
	for i := 0; i < count; i++ {
		offset, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(length-i)))
		if err != nil {
			panic(err)
		}
		j := i + int(offset.Int64())
		indices[i], indices[j] = indices[j], indices[i]
	}
	return indices[:count]
}

// ByteCountSI converts bytes to a human-readable format
func ByteCountSI(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB",
		float64(b)/float64(div), "kMGTPE"[exp])
}

var regexRandomString = regexp.MustCompile(`[^a-zA-Z0-9]+`)

// Removes special characters from string
func cleanRandomString(input string) string {
	return regexRandomString.ReplaceAllString(input, "")
}

var regexContent = regexp.MustCompile(`[^a-zA-Z0-9/ \-=\+\.]+`)

// SanitiseContentType removes invalid characters from the contentType string
// or returns default when too long or too short
func SanitiseContentType(contentType string) string {
	if len(contentType) > 100 || len(strings.TrimSpace(contentType)) < 2 {
		return "application/octet-stream"
	}
	return regexContent.ReplaceAllString(contentType, "")
}

// Remove characters that are dangerous in filenames on common OSes or in HTTP headers:
//
//	/ \ : * ? " < > |  — forbidden on Windows and/or meaningful on Unix
//	\r \n                — would break HTTP header injection
var regexFileName = regexp.MustCompile(`[/\\:*?"<>|\r\n]`)

// SanitiseFilename removes or replaces characters from a filename that could be
// used for path traversal, header injection, or shell injection attacks.
// It preserves the base name only (strips any directory components), then
// removes ASCII control characters and the following special characters:
// / \ : * ? " < > | null byte, and trims leading dots to prevent hidden files.
// String is limited to 400 characters
func SanitiseFilename(name string) string {
	// Remove null bytes and ASCII control characters (0x00–0x1F, 0x7F), limit string length
	var b strings.Builder
	if len(name) > 400 {
		name = name[0:400] + "..."
	}
	for _, r := range name {
		if r == 0x00 || (r >= 0x01 && r <= 0x1F) || r == 0x7F {
			continue
		}
		b.WriteRune(r)
	}
	name = b.String()

	name = regexFileName.ReplaceAllString(name, "_")

	// Trim leading dots to prevent hidden files (e.g. ".bashrc", "..foo")
	name = strings.TrimLeft(name, ".")

	return strings.TrimSpace(name)
}
