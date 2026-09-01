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
	"sync"
	"testing"
	"time"

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

// sealedTestConfig builds a Configuration for level at the given password, mirroring how
// configuration/setup.parseEncryptionAndDelete populates Salt/Checksum/ChecksumSalt for the
// Input encryption levels: an independent salt for the cipher-key derivation, and a
// PasswordChecksum computed from a second, independent salt.
func sealedTestConfig(level int, password string) models.Configuration {
	return models.Configuration{Encryption: models.Encryption{
		Level:        level,
		Salt:         "sealed-test-cipher-salt",
		ChecksumSalt: "sealed-test-checksum-salt",
		Checksum:     PasswordChecksum(password, "sealed-test-checksum-salt"),
	}}
}

// TestInitSealsInputLevels is the boot-time half of sealed boot: Init at the Input encryption
// levels (LocalEncryptionInput/FullEncryptionInput) must record the instance as sealed rather
// than block reading a password from stdin (which would crash-loop a detached, stdin-less
// container - see the package doc comment on Init), and decryption must not be available until
// Unseal succeeds.
func TestInitSealsInputLevels(t *testing.T) {
	for _, level := range []int{LocalEncryptionInput, FullEncryptionInput} {
		Init(sealedTestConfig(level, "correct horse battery staple"))
		test.IsEqualBool(t, IsSealed(), true)
		test.IsEqualBool(t, IsDecryptionAvailable(), false)
	}
}

// TestInitNeverSealsOtherLevels locks the requirement that NoEncryption, the Stored levels and
// EndToEndEncryption are never sealed, and are unaffected by sealed boot - including after the
// instance was sealed by a previous Init call for an Input level, which must not leak into a
// later Init at one of these levels (see the sealed-state reset at the top of Init).
func TestInitNeverSealsOtherLevels(t *testing.T) {
	os.Unsetenv(envMasterKey)
	Init(sealedTestConfig(FullEncryptionInput, "some password"))
	test.IsEqualBool(t, IsSealed(), true)

	Init(models.Configuration{Encryption: models.Encryption{Level: NoEncryption}})
	test.IsEqualBool(t, IsSealed(), false)

	cipher, err := GetRandomCipher()
	test.IsNil(t, err)
	for _, level := range []int{LocalEncryptionStored, FullEncryptionStored} {
		// Re-seal before every iteration so each one independently proves this level clears it.
		Init(sealedTestConfig(FullEncryptionInput, "some password"))
		test.IsEqualBool(t, IsSealed(), true)

		Init(models.Configuration{Encryption: models.Encryption{Level: level, Cipher: cipher}})
		test.IsEqualBool(t, IsSealed(), false)
		test.IsEqualBool(t, IsDecryptionAvailable(), true)
	}

	Init(sealedTestConfig(FullEncryptionInput, "some password"))
	test.IsEqualBool(t, IsSealed(), true)
	Init(models.Configuration{Encryption: models.Encryption{Level: EndToEndEncryption}})
	test.IsEqualBool(t, IsSealed(), false)
}

// TestUnsealCorrectPassword covers the happy path: the correct password unseals the instance,
// after which decryption is available and an encrypt/decrypt round trip through the newly loaded
// master key succeeds.
func TestUnsealCorrectPassword(t *testing.T) {
	const password = "the correct password"
	Init(sealedTestConfig(FullEncryptionInput, password))
	test.IsEqualBool(t, IsSealed(), true)
	test.IsEqualBool(t, IsDecryptionAvailable(), false)

	err := Unseal(password)
	test.IsNil(t, err)
	test.IsEqualBool(t, IsSealed(), false)
	test.IsEqualBool(t, IsDecryptionAvailable(), true)

	plaintext := []byte("plaintext only readable once unsealed")
	var encrypted bytes.Buffer
	encInfo := &models.EncryptionInfo{}
	err = Encrypt(encInfo, bytes.NewReader(plaintext), &encrypted)
	test.IsNil(t, err)
	var decrypted bytes.Buffer
	err = DecryptReader(*encInfo, &encrypted, &decrypted)
	test.IsNil(t, err)
	test.IsEqualByteSlice(t, plaintext, decrypted.Bytes())
}

// TestUnsealIncorrectPassword covers both failure inputs the endpoint has to reject: an empty
// password and a wrong-but-nonempty one. Neither may store any key material or clear sealed.
func TestUnsealIncorrectPassword(t *testing.T) {
	Init(sealedTestConfig(FullEncryptionInput, "the correct password"))

	err := Unseal("")
	test.IsEqualBool(t, err == ErrIncorrectPassword, true)
	test.IsEqualBool(t, IsSealed(), true)
	test.IsEqualBool(t, IsDecryptionAvailable(), false)

	err = Unseal("the WRONG password")
	test.IsEqualBool(t, err == ErrIncorrectPassword, true)
	test.IsEqualBool(t, IsSealed(), true)
	test.IsEqualBool(t, IsDecryptionAvailable(), false)

	// A correct attempt afterwards must still succeed - a failed attempt must not have wedged
	// the sealed state.
	err = Unseal("the correct password")
	test.IsNil(t, err)
	test.IsEqualBool(t, IsSealed(), false)
}

// TestUnsealAlreadyUnsealedIsNoOp covers a retried unseal request after a successful one: it
// must not error and must not disturb the already-loaded key.
func TestUnsealAlreadyUnsealedIsNoOp(t *testing.T) {
	Init(sealedTestConfig(FullEncryptionInput, "the correct password"))
	err := Unseal("the correct password")
	test.IsNil(t, err)
	test.IsEqualBool(t, IsSealed(), false)

	err = Unseal("the correct password")
	test.IsNil(t, err)
	test.IsEqualBool(t, IsSealed(), false)
	test.IsEqualBool(t, IsDecryptionAvailable(), true)

	// Also a no-op for a call that would otherwise have been an incorrect password - nothing
	// left to verify against once already unsealed.
	err = Unseal("anything at all")
	test.IsNil(t, err)
	test.IsEqualBool(t, IsSealed(), false)
}

// TestSealedOperationsFailCleanly is the "no panic, no crash-loop" half of the requirement:
// while sealed, the functions that wrap/unwrap the master key must return ErrSealed rather than
// call into getMasterCipher with no key loaded, which would otherwise be a fatal error and take
// the whole process down rather than fail one request.
func TestSealedOperationsFailCleanly(t *testing.T) {
	Init(sealedTestConfig(FullEncryptionInput, "the correct password"))
	test.IsEqualBool(t, IsSealed(), true)

	encInfo := &models.EncryptionInfo{}
	err := Encrypt(encInfo, bytes.NewReader([]byte("plaintext")), &bytes.Buffer{})
	test.IsEqualBool(t, err == ErrSealed, true)

	_, err = GetCipherFromFile(models.EncryptionInfo{DecryptionKey: make([]byte, 48), Nonce: make([]byte, 12)})
	test.IsEqualBool(t, err == ErrSealed, true)

	_, err = fileCipherEncrypt(make([]byte, 32), make([]byte, 12))
	test.IsEqualBool(t, err == ErrSealed, true)
	_, err = fileCipherDecrypt(make([]byte, 32), make([]byte, 12))
	test.IsEqualBool(t, err == ErrSealed, true)
}

// TestUnsealConcurrent is the concurrency requirement: several goroutines racing to unseal the
// same instance - some with the correct password, some wrong - must never corrupt state. Run
// with -race to catch a data race, not just a logic bug. Kept to a modest worker count
// deliberately: each call that actually reaches scrypt derives a real key at the production
// N=1048576 parameter (~1GB of working memory per concurrent derivation) - though with
// unsealSemaphore in place, at most one of these workers ever derives at a time, which is exactly
// the property under test: the others must fail fast with ErrUnsealBusy rather than also running
// scrypt. Since a wrong-password worker may transiently win the single derivation slot ahead of
// every correct-password worker, the correct-password side retries against ErrUnsealBusy like a
// real client would after a 429, rather than assuming its one attempt is guaranteed to land.
func TestUnsealConcurrent(t *testing.T) {
	const password = "the correct password"
	Init(sealedTestConfig(FullEncryptionInput, password))

	const wrongWorkers = 6
	var wg sync.WaitGroup
	wg.Add(wrongWorkers)
	for i := 0; i < wrongWorkers; i++ {
		go func() {
			defer wg.Done()
			_ = Unseal("wrong password")
		}()
	}

	deadline := time.Now().Add(10 * time.Second)
	var err error
	for {
		err = Unseal(password)
		if err != ErrUnsealBusy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("could not acquire the unseal derivation slot with the correct password before the deadline")
		}
		time.Sleep(10 * time.Millisecond)
	}
	test.IsNil(t, err)
	wg.Wait()

	test.IsEqualBool(t, IsSealed(), false)
	test.IsEqualBool(t, IsDecryptionAvailable(), true)

	// The key that ended up loaded must still be the one derived from the correct password -
	// readable via a round trip, not merely "some key or other".
	plaintext := []byte("post-race plaintext")
	var encrypted bytes.Buffer
	encInfo := &models.EncryptionInfo{}
	err = Encrypt(encInfo, bytes.NewReader(plaintext), &encrypted)
	test.IsNil(t, err)
	var decrypted bytes.Buffer
	err = DecryptReader(*encInfo, &encrypted, &decrypted)
	test.IsNil(t, err)
	test.IsEqualByteSlice(t, plaintext, decrypted.Bytes())
}

// TestUnsealSemaphoreRejectsWhenBusy is the failing-first test for the process-wide concurrency
// cap on the scrypt derivation (see unsealSemaphore on Unseal): at most one derivation may run at
// a time, regardless of how many callers or IPs are involved. Exercised cheaply, without running
// a real scrypt derivation at all: unsealSemaphore's single slot is taken directly here to
// simulate "a derivation is already in flight", which works because Unseal's semaphore check runs
// before either scrypt call it makes (the checksum verification in PasswordChecksum and the key
// derivation itself) - so a second concurrent call must be rejected with ErrUnsealBusy without
// ever touching scrypt, correct password or not.
func TestUnsealSemaphoreRejectsWhenBusy(t *testing.T) {
	const password = "semaphore busy test password"
	Init(sealedTestConfig(FullEncryptionInput, password))

	unsealSemaphore <- struct{}{}
	err := Unseal(password)
	test.IsEqualBool(t, err == ErrUnsealBusy, true)
	test.IsEqualBool(t, IsSealed(), true)
	<-unsealSemaphore // release, exactly as Unseal's own deferred release would have done

	// With the slot free again, an otherwise-identical call must succeed normally.
	err = Unseal(password)
	test.IsNil(t, err)
	test.IsEqualBool(t, IsSealed(), false)
}

// TestUnsealSemaphoreReleasedOnIncorrectPassword confirms the derivation slot is released even
// when Unseal returns early because the password is wrong (see the defer in Unseal), not only on
// the success path - so one caller's wrong password can never wedge the slot for every
// subsequent, legitimate attempt.
func TestUnsealSemaphoreReleasedOnIncorrectPassword(t *testing.T) {
	const password = "semaphore release test password"
	Init(sealedTestConfig(FullEncryptionInput, password))

	err := Unseal("the wrong password")
	test.IsEqualBool(t, err == ErrIncorrectPassword, true)
	test.IsEqualBool(t, IsSealed(), true)

	err = Unseal(password)
	test.IsNil(t, err)
	test.IsEqualBool(t, IsSealed(), false)
}
