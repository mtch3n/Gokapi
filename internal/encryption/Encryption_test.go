package encryption

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"github.com/forceu/gokapi/internal/models"
	"github.com/forceu/gokapi/internal/test"
	"io"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/scrypt"
)

// Note: most of these tests are written by AI

func TestGetRandomCipher(t *testing.T) {
	cipher1, err := GetRandomCipher()
	test.IsNil(t, err)
	test.IsEqualInt(t, len(cipher1), 32)
	cipher2, err := GetRandomCipher()
	test.IsNil(t, err)
	isEqual := bytes.Compare(cipher1, cipher2)
	test.IsEqualBool(t, isEqual != 0, true)
}

func TestInit(t *testing.T) {
	os.Unsetenv(envMasterKey)
	config := models.Configuration{
		Encryption: models.Encryption{
			Level:  NoEncryption,
			Cipher: []byte("01234567890123456789012345678901"),
		},
	}
	Init(config)
	// Testing for no encryption, nothing should change

	config.Encryption.Level = LocalEncryptionStored
	Init(config)
	test.IsNotNil(t, ramCipher)
	test.IsNotNil(t, encryptedKey)
	test.IsEqualByteSlice(t, getMasterCipher(), config.Encryption.Cipher)

	config.Encryption.Level = FullEncryptionStored
	Init(config)
	test.IsNotNil(t, ramCipher)
	test.IsNotNil(t, encryptedKey)
	test.IsEqualByteSlice(t, getMasterCipher(), config.Encryption.Cipher)
}

func TestInitWithExternalKey(t *testing.T) {
	defer os.Unsetenv(envMasterKey)
	externalKey := []byte("abcdefghijklmnopqrstuvwxyz012345")
	os.Setenv(envMasterKey, base64.StdEncoding.EncodeToString(externalKey))
	config := models.Configuration{
		Encryption: models.Encryption{
			Level:  LocalEncryptionStored,
			Cipher: []byte("01234567890123456789012345678901"),
		},
	}
	Init(config)
	// The external key has to be used instead of the config cipher
	test.IsEqualByteSlice(t, getMasterCipher(), externalKey)

	config.Encryption.Level = FullEncryptionStored
	Init(config)
	test.IsEqualByteSlice(t, getMasterCipher(), externalKey)
}

func TestGetExternalKey(t *testing.T) {
	defer os.Unsetenv(envMasterKey)
	os.Unsetenv(envMasterKey)
	key, err := getExternalKey(LocalEncryptionStored)
	test.IsNil(t, err)
	test.IsEqualBool(t, key == nil, true)

	externalKey := []byte("abcdefghijklmnopqrstuvwxyz012345")
	os.Setenv(envMasterKey, base64.StdEncoding.EncodeToString(externalKey))
	key, err = getExternalKey(LocalEncryptionStored)
	test.IsNil(t, err)
	test.IsEqualByteSlice(t, key, externalKey)
	key, err = getExternalKey(FullEncryptionStored)
	test.IsNil(t, err)
	test.IsEqualByteSlice(t, key, externalKey)

	// Setting the variable at a level without a stored key has to be rejected
	for _, level := range []int{NoEncryption, LocalEncryptionInput, FullEncryptionInput, EndToEndEncryption} {
		_, err = getExternalKey(level)
		test.IsNotNil(t, err)
	}

	os.Setenv(envMasterKey, "not-valid-base64!")
	_, err = getExternalKey(LocalEncryptionStored)
	test.IsNotNil(t, err)

	os.Setenv(envMasterKey, base64.StdEncoding.EncodeToString([]byte("tooshort")))
	_, err = getExternalKey(LocalEncryptionStored)
	test.IsNotNil(t, err)

	os.Setenv(envMasterKey, base64.StdEncoding.EncodeToString(append(externalKey, 'x')))
	_, err = getExternalKey(FullEncryptionStored)
	test.IsNotNil(t, err)
}

func TestPasswordChecksum(t *testing.T) {
	password := "securepassword"
	salt := "somesalt"
	checksum := PasswordChecksum(password, salt)
	expectedChecksum, err := scrypt.Key([]byte(password), []byte(salt), 1048576, 8, 1, blockSize)
	test.IsNil(t, err)
	hasher := sha256.New()
	hasher.Write(expectedChecksum)
	test.IsEqualString(t, hex.EncodeToString(hasher.Sum(nil)), checksum)
	checksum = PasswordChecksum("testpw", "testsalt")
	test.IsEqualString(t, checksum, "30161cdf03347d6d3f99743532b8523e03e79d4d91ddd3a623be414519ee9ca9")
	checksum = PasswordChecksum("testpw", "test")
	test.IsEqualString(t, checksum, "41d1781205837071affbf2268588b3f2e755f0365cfe16aff6136155c1013029")
	checksum = PasswordChecksum("test", "test")
	test.IsEqualString(t, checksum, "a3325e881a99e897aab8ba1de274803cddd4f035409c98e976fec9b8005694e6")
	checksum = PasswordChecksum("test", "testsalt")
	test.IsEqualString(t, checksum, "2dbcdfd0989dd2e1be0eea54f176c102e891fd4cb8182544fa4c9dba45307846")
}

func TestEncryptDecryptBytes(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	test.IsNil(t, err)

	nonce := make([]byte, 12)
	_, err = rand.Read(nonce)
	test.IsNil(t, err)

	plaintext := []byte("this is some plaintext")

	ciphertext, err := EncryptDecryptBytes(plaintext, key, nonce, true)
	test.IsNil(t, err)

	decrypted, err := EncryptDecryptBytes(ciphertext, key, nonce, false)
	test.IsNil(t, err)
	test.IsEqualByteSlice(t, plaintext, decrypted)
}

func TestGenerateNewFileKey(t *testing.T) {
	encInfo := &models.EncryptionInfo{}
	key, err := generateNewFileKey(encInfo)
	test.IsNil(t, err)
	test.IsEqualInt(t, 32, len(key))
	test.IsEqualInt(t, 12, len(encInfo.Nonce))
	test.IsEqualBool(t, encInfo.IsEncrypted, true)
	test.IsEqualInt(t, 48, len(encInfo.DecryptionKey))
}

func TestEncryptDecrypt(t *testing.T) {
	plaintext := []byte("this is some plaintext")
	input := bytes.NewReader(plaintext)
	var encrypted bytes.Buffer
	encInfo := &models.EncryptionInfo{}

	err := Encrypt(encInfo, input, &encrypted)
	test.IsNil(t, err)

	var decrypted bytes.Buffer
	err = DecryptReader(*encInfo, &encrypted, &decrypted)
	test.IsNil(t, err)
	test.IsEqualByteSlice(t, plaintext, decrypted.Bytes())
}

func TestGetRandomData(t *testing.T) {
	data, err := getRandomData(32)
	test.IsNil(t, err)
	test.IsEqualInt(t, 32, len(data))
}

func TestCalculateEncryptedFilesize(t *testing.T) {
	size := int64(1024)
	encryptedSize := CalculateEncryptedFilesize(size)
	test.IsEqualBool(t, encryptedSize > size, true)
}

func TestGetStream(t *testing.T) {
	key, err := GetRandomCipher()
	test.IsNil(t, err)
	stream := getStream(key)
	test.IsNotNil(t, stream)
}

func TestStoreMasterKey(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	test.IsNil(t, err)

	storeMasterKey(key)
	test.IsNotNil(t, ramCipher)
	test.IsNotNil(t, encryptedKey)
}

func TestFileCipherEncryptDecrypt(t *testing.T) {
	input := []byte("testdata")
	nonce, err := GetRandomNonce()
	test.IsNil(t, err)

	encrypted, err := fileCipherEncrypt(input, nonce)
	test.IsNil(t, err)

	decrypted, err := fileCipherDecrypt(encrypted, nonce)
	test.IsNil(t, err)
	test.IsEqualByteSlice(t, input, decrypted)
}

func TestGetCipherFromFile(t *testing.T) {
	// Initialize the encryption key and nonce
	encInfo := &models.EncryptionInfo{
		DecryptionKey: make([]byte, 32),
		Nonce:         make([]byte, 12),
	}
	_, err := rand.Read(encInfo.DecryptionKey)
	test.IsNil(t, err)
	_, err = rand.Read(encInfo.Nonce)
	test.IsNil(t, err)

	// Set the master key and ram cipher
	key := make([]byte, 32)
	_, err = rand.Read(key)
	test.IsNil(t, err)
	storeMasterKey(key)

	// Encrypt a sample key to store in encInfo.DecryptionKey
	encKey, err := fileCipherEncrypt(key, encInfo.Nonce)
	test.IsNil(t, err)
	encInfo.DecryptionKey = encKey

	// Retrieve the cipher from the file info
	retrievedKey, err := GetCipherFromFile(*encInfo)
	test.IsNil(t, err)
	test.IsEqualInt(t, 32, len(retrievedKey))
	test.IsEqualByteSlice(t, key, retrievedKey)
}

// TestEncryptGeneratesFreshKeyPerCall locks the invariant that makes the
// all-zero stream nonce in Encrypt safe: every call must draw a fresh key,
// even if it is asked to encrypt byte-identical plaintext. Encrypt itself
// has no notion of deduplication - it always encrypts what it is given
// under a brand new key - so this must hold unconditionally. (Storage-layer
// deduplication for identical content, which intentionally reuses a key
// instead of calling Encrypt again, is a separate, safe exception covered
// by TestNewFileFromChunkDedupReusesKeyAndCiphertext in the storage
// package; what would be catastrophic is a key covering two *different*
// plaintexts, which is what this test guards against.)
func TestEncryptGeneratesFreshKeyPerCall(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	test.IsNil(t, err)
	storeMasterKey(key)

	plaintext := []byte("identical content passed to Encrypt twice")

	encInfo1 := &models.EncryptionInfo{}
	var ciphertext1 bytes.Buffer
	err = Encrypt(encInfo1, bytes.NewReader(plaintext), &ciphertext1)
	test.IsNil(t, err)

	encInfo2 := &models.EncryptionInfo{}
	var ciphertext2 bytes.Buffer
	err = Encrypt(encInfo2, bytes.NewReader(plaintext), &ciphertext2)
	test.IsNil(t, err)

	test.IsEqualBool(t, bytes.Equal(encInfo1.DecryptionKey, encInfo2.DecryptionKey), false)
	test.IsEqualBool(t, bytes.Equal(encInfo1.Nonce, encInfo2.Nonce), false)
	test.IsEqualBool(t, bytes.Equal(ciphertext1.Bytes(), ciphertext2.Bytes()), false)

	// Both must still decrypt correctly with their own, independently generated key.
	var decrypted1, decrypted2 bytes.Buffer
	err = DecryptReader(*encInfo1, &ciphertext1, &decrypted1)
	test.IsNil(t, err)
	err = DecryptReader(*encInfo2, &ciphertext2, &decrypted2)
	test.IsNil(t, err)
	test.IsEqualByteSlice(t, plaintext, decrypted1.Bytes())
	test.IsEqualByteSlice(t, plaintext, decrypted2.Bytes())
}

// TestGenerateNewFileKeyNeverRepeats guards the same invariant one level
// down: the generator that Encrypt relies on must never draw the same key
// twice. This is what actually makes the zero stream nonce safe to use.
func TestGenerateNewFileKeyNeverRepeats(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	test.IsNil(t, err)
	storeMasterKey(key)

	const draws = 1000
	seen := make(map[string]bool, draws)
	for i := 0; i < draws; i++ {
		encInfo := &models.EncryptionInfo{}
		fileKey, err := generateNewFileKey(encInfo)
		test.IsNil(t, err)
		hexKey := hex.EncodeToString(fileKey)
		test.IsEqualBool(t, seen[hexKey], false)
		seen[hexKey] = true
	}
}

func TestIsCorrectKey(t *testing.T) {
	// Create a temporary file for testing
	file, err := os.CreateTemp("", "testfile")
	test.IsNil(t, err)
	defer os.Remove(file.Name())

	// Write some encrypted data to the file
	encInfo := &models.EncryptionInfo{
		DecryptionKey: make([]byte, 32),
		Nonce:         make([]byte, 12),
	}
	_, err = rand.Read(encInfo.DecryptionKey)
	test.IsNil(t, err)
	_, err = rand.Read(encInfo.Nonce)
	test.IsNil(t, err)

	plaintext := []byte("this is some plaintext")
	input := bytes.NewReader(plaintext)
	err = Encrypt(encInfo, input, file)
	test.IsNil(t, err)

	// Re-open the file for reading
	_, err = file.Seek(0, io.SeekStart)
	test.IsNil(t, err)

	// Test if the key is correct
	isCorrect := IsCorrectKey(*encInfo, file)
	test.IsEqualBool(t, isCorrect, true)
}

// TestEncryptDecryptStringRoundTrip is the round-trip test for the share-password helper (see
// storage.GetSharePassword): representative inputs - plain ASCII, unicode, a long string, and
// the empty string - must all come back byte-for-byte identical, and two encryptions of the
// same plaintext must not produce the same ciphertext (a fresh random nonce every call).
func TestEncryptDecryptStringRoundTrip(t *testing.T) {
	key, err := GetRandomCipher()
	test.IsNil(t, err)
	Init(models.Configuration{Encryption: models.Encryption{Level: FullEncryptionStored, Cipher: key}})

	inputs := []string{
		"simple-ascii-password",
		"unicode: 日本語パスワード 🔒🔑 émoji café",
		strings.Repeat("a-very-long-generated-share-password-segment-", 500),
		"",
	}
	for _, plaintext := range inputs {
		encrypted, err := EncryptString(plaintext)
		test.IsNil(t, err)
		decrypted, err := DecryptString(encrypted)
		test.IsNil(t, err)
		test.IsEqualString(t, decrypted, plaintext)
	}

	// Two encryptions of the same plaintext must differ (random nonce per call), yet both must
	// still decrypt to the same value.
	const samePlaintext = "same-password-twice"
	encryptedA, err := EncryptString(samePlaintext)
	test.IsNil(t, err)
	encryptedB, err := EncryptString(samePlaintext)
	test.IsNil(t, err)
	test.IsEqualBool(t, bytes.Equal(encryptedA, encryptedB), false)
	decryptedA, err := DecryptString(encryptedA)
	test.IsNil(t, err)
	decryptedB, err := DecryptString(encryptedB)
	test.IsNil(t, err)
	test.IsEqualString(t, decryptedA, samePlaintext)
	test.IsEqualString(t, decryptedB, samePlaintext)
}

// TestEncryptDecryptStringNoMasterKey covers the safe no-op path: DecryptString must fail
// rather than panic or return garbage when handed a payload too short to contain a nonce, and
// EncryptString/DecryptString both refuse to run once the master key has never been loaded.
func TestEncryptDecryptStringNoMasterKey(t *testing.T) {
	_, err := DecryptString([]byte("short"))
	test.IsNotNil(t, err)

	previousRamCipher, previousEncryptedKey := ramCipher, encryptedKey
	defer func() { ramCipher, encryptedKey = previousRamCipher, previousEncryptedKey }()
	ramCipher, encryptedKey = nil, nil

	_, err = EncryptString("some-password")
	test.IsNotNil(t, err)
	test.IsEqualBool(t, err == ErrMasterKeyUnavailable, true)

	_, err = DecryptString([]byte("0123456789012345678901234567890123456789"))
	test.IsNotNil(t, err)
	test.IsEqualBool(t, err == ErrMasterKeyUnavailable, true)
}
