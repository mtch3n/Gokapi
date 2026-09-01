package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sync"

	"github.com/forceu/gokapi/internal/models"
	"github.com/secure-io/sio-go"
	"golang.org/x/crypto/scrypt"
)

// NoEncryption means all files are stored in plaintext
const NoEncryption = 0

// LocalEncryptionStored means remote files are stored in plaintext, cipher for local files is in plaintext
const LocalEncryptionStored = 1

// LocalEncryptionInput means remote files are stored in plaintext, password needs to be entered on startup
const LocalEncryptionInput = 2

// FullEncryptionStored means all files are encrypted, cipher for local files is in plaintext
const FullEncryptionStored = 3

// FullEncryptionInput means all files are encrypted, password needs to be entered on startup
const FullEncryptionInput = 4

// EndToEndEncryption means all files are encrypted and decrypted client-side
const EndToEndEncryption = 5

// mu guards every package-level variable below: the sealed/unsealed flag, the salts/checksum
// recorded for a sealed instance, and the in-memory master key material itself. Unseal can be
// called concurrently (e.g. several admins racing to submit the password, or a retried request),
// so every read or write of this state goes through mu rather than relying on it only ever being
// touched from one goroutine at startup, which was true before sealed boot existed.
var mu sync.Mutex

var encryptedKey, ramCipher []byte

// sealed is true only for the Input encryption levels (LocalEncryptionInput/FullEncryptionInput)
// before a successful Unseal call. It is always false for every other level - see Init.
var sealed bool

// sealedSalt, sealedChecksum and sealedChecksumSalt are the values Init recorded for a sealed
// instance, kept in memory only so Unseal can later reproduce and verify the scrypt derivation
// without having to re-read the configuration.
var sealedSalt, sealedChecksum, sealedChecksumSalt string

// IsDecryptionAvailable returns true if the master encryption key has been
// loaded into memory, meaning server-side decryption is possible. Always false while the
// instance is sealed, even though the fields backing it may still hold a stale key from before
// a previous Init - IsSealed is authoritative on whether that key may be used.
func IsDecryptionAvailable() bool {
	mu.Lock()
	defer mu.Unlock()
	return !sealed && len(ramCipher) > 0
}

// IsSealed returns true if the instance is running at an Input encryption level
// (LocalEncryptionInput or FullEncryptionInput) and has not yet been unsealed with the correct
// password via Unseal. Always false at every other level: NoEncryption never has a key to seal,
// LocalEncryptionStored/FullEncryptionStored load their key from the stored cipher at Init, and
// EndToEndEncryption never holds a server-side key capable of decrypting anything in the first
// place.
func IsSealed() bool {
	mu.Lock()
	defer mu.Unlock()
	return sealed
}

// ErrSealed is returned by encryption operations that need the master key while the instance is
// still sealed (see IsSealed). Callers that can produce a clearer, user-facing refusal (e.g. the
// webserver/storage packages) should check IsSealed themselves before reaching this point; this
// is the last line of defence that keeps fileCipherEncrypt/fileCipherDecrypt from ever calling
// into getMasterCipher with no key loaded, which would otherwise be a fatal error.
var ErrSealed = errors.New("instance is sealed")

// ErrIncorrectPassword is returned by Unseal when the supplied password is empty or does not
// match the checksum recorded when the instance was configured. The instance remains sealed.
var ErrIncorrectPassword = errors.New("incorrect password provided")

// ErrUnsealBusy is returned by Unseal when another unseal derivation is already in flight
// process-wide (see unsealSemaphore). The caller (POST /api/unseal) should answer 429/503
// immediately rather than retry inline - retrying right away would just contend for the same
// single derivation slot again.
var ErrUnsealBusy = errors.New("an unseal derivation is already in progress")

// unsealSemaphore bounds the expensive part of Unseal (the scrypt derivation, both the checksum
// verification and the key derivation itself - see PasswordChecksum and the scrypt.Key call
// below) to exactly one in flight at a time, process-wide. Each derivation uses N=2^20
// (~1 GiB of working memory, 1-2s of CPU); without this cap, an unauthenticated caller could
// force many derivations to run concurrently via POST /api/unseal and exhaust memory. Acquired
// with a non-blocking send so a caller that cannot get the single slot fails fast with
// ErrUnsealBusy instead of queueing behind (and thereby holding open a connection for) whichever
// derivation is already running.
var unsealSemaphore = make(chan struct{}, 1)

const blockSize = 32
const nonceSize = 12

// envMasterKey is the name of the environment variable that can supply the master key
// externally, e.g. resolved from a secret store into the environment before startup
const envMasterKey = "GOKAPI_ENCRYPTION_KEY_B64"

// Init needs to be called to load the master key into memory, or - for the Input encryption
// levels (LocalEncryptionInput/FullEncryptionInput) - to record the instance as sealed. It never
// reads from stdin and never blocks: those levels derive their key from a password only, and a
// server running detached (e.g. in a container, with no attached terminal) must still be able to
// start and serve. The instance stays sealed until an admin calls Unseal with the correct
// password, typically over the webserver's /api/unseal endpoint.
func Init(config models.Configuration) {
	externalKey, err := getExternalKey(config.Encryption.Level)
	if err != nil {
		log.Fatal(err)
	}
	// Init fully determines the sealed state from the supplied config on every call - a level
	// that does not need sealing (or a fresh call to Init itself) must not leave the instance
	// sealed from a previous configuration. Levels 2/4 set sealed back to true immediately below
	// via initSealed.
	mu.Lock()
	sealed = false
	sealedSalt, sealedChecksum, sealedChecksumSalt = "", "", ""
	mu.Unlock()
	switch config.Encryption.Level {
	case NoEncryption:
		return
	case LocalEncryptionStored, FullEncryptionStored:
		if externalKey != nil {
			initWithCipher(externalKey)
			return
		}
		initWithCipher(config.Encryption.Cipher)
	case LocalEncryptionInput, FullEncryptionInput:
		initSealed(config.Encryption.Salt, config.Encryption.Checksum, config.Encryption.ChecksumSalt)
	case EndToEndEncryption:
		return
	}
}

// initSealed records the instance as sealed and stores the salts/checksum Unseal will later need
// to derive and verify the master key. An empty salt means the configuration itself is broken
// (not merely "not unsealed yet"), so that case still fails startup immediately, exactly as it
// did before sealed boot existed.
func initSealed(saltPw, expectedChecksum, saltChecksum string) {
	if saltPw == "" || saltChecksum == "" {
		log.Fatal("Empty salt provided. Please rerun setup with --reconfigure")
	}
	mu.Lock()
	defer mu.Unlock()
	sealed = true
	sealedSalt = saltPw
	sealedChecksum = expectedChecksum
	sealedChecksumSalt = saltChecksum
}

// Unseal derives the master key from password and loads it into memory, using the same scrypt
// parameters and checksum verification that the (now removed) interactive stdin prompt used to.
// Safe to call repeatedly and concurrently: the password is verified against the checksum
// recorded by Init before anything is mutated, so a wrong or empty password never touches the
// stored key material and the instance simply stays sealed. Returns nil (and leaves the instance
// unsealed) if it was already unsealed, so a retried request after a successful unseal is a
// harmless no-op rather than an error. Returns ErrUnsealBusy without deriving anything if another
// derivation is already in flight (see unsealSemaphore) - the caller should turn that into a 429,
// not retry inline.
func Unseal(password string) error {
	mu.Lock()
	if !sealed {
		mu.Unlock()
		return nil
	}
	saltPw, expectedChecksum, saltChecksum := sealedSalt, sealedChecksum, sealedChecksumSalt
	mu.Unlock()

	if password == "" {
		return ErrIncorrectPassword
	}

	select {
	case unsealSemaphore <- struct{}{}:
	default:
		return ErrUnsealBusy
	}
	defer func() { <-unsealSemaphore }()

	if PasswordChecksum(password, saltChecksum) != expectedChecksum {
		return ErrIncorrectPassword
	}
	cipherKey, err := scrypt.Key([]byte(password), []byte(saltPw), 1048576, 8, 1, blockSize)
	if err != nil {
		return err
	}

	mu.Lock()
	defer mu.Unlock()
	if !sealed {
		// Another goroutine won the race and unsealed the instance while this call was
		// deriving the key above; nothing left to do.
		return nil
	}
	storeMasterKeyLocked(cipherKey)
	sealed = false
	return nil
}

// AcquireUnsealSemaphoreForTesting takes the process-wide unseal derivation slot (see
// unsealSemaphore) without running a real scrypt derivation, so tests in other packages (e.g.
// webserver/api) can cheaply simulate "a derivation is already in flight" and verify that a
// concurrent Unseal/apiUnseal call is rejected with ErrUnsealBusy instead of also deriving.
// Returns false if the slot was already held. The caller must release it again via
// ReleaseUnsealSemaphoreForTesting once done.
func AcquireUnsealSemaphoreForTesting() bool {
	select {
	case unsealSemaphore <- struct{}{}:
		return true
	default:
		return false
	}
}

// ReleaseUnsealSemaphoreForTesting releases the slot taken by
// AcquireUnsealSemaphoreForTesting.
func ReleaseUnsealSemaphoreForTesting() {
	<-unsealSemaphore
}

// getExternalKey reads the master key from the environment variable envMasterKey and returns
// nil if the variable is not set. An error is returned if the key is invalid or the variable
// is set at an encryption level that does not use a stored key, as a silently ignored or
// wrong key would make all stored files unreadable
func getExternalKey(encLevel int) ([]byte, error) {
	value := os.Getenv(envMasterKey)
	if value == "" {
		return nil, nil
	}
	if encLevel != LocalEncryptionStored && encLevel != FullEncryptionStored {
		return nil, fmt.Errorf("%s is set, but encryption level %d does not use a stored master key. Unset the variable or rerun setup with --reconfigure", envMasterKey, encLevel)
	}
	key, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s is not valid base64: %v", envMasterKey, err)
	}
	if len(key) != blockSize {
		return nil, fmt.Errorf("%s has to decode to exactly %d bytes, but decodes to %d bytes", envMasterKey, blockSize, len(key))
	}
	return key, nil
}

// PasswordChecksum creates a checksum which is used to check if the supplied password is correct
func PasswordChecksum(pw, salt string) string {
	cipherKey, err := scrypt.Key([]byte(pw), []byte(salt), 1048576, 8, 1, blockSize)
	if err != nil {
		cipherKey = []byte{}
		log.Fatal(err)
	}

	hasher := sha256.New()
	hasher.Write(cipherKey)
	return hex.EncodeToString(hasher.Sum(nil))
}

func initWithCipher(cipherKey []byte) {
	if len(cipherKey) != 32 {
		log.Fatal("Invalid cipher provided. Please rerun setup with --reconfigure")
	}
	storeMasterKey(cipherKey)
}

func storeMasterKey(cipherKey []byte) {
	mu.Lock()
	defer mu.Unlock()
	storeMasterKeyLocked(cipherKey)
}

// storeMasterKeyLocked is storeMasterKey's body, split out so Unseal can call it while it already
// holds mu (see Unseal) without deadlocking on a second lock attempt.
func storeMasterKeyLocked(cipherKey []byte) {
	var err error
	ramCipher, err = getRandomData(blockSize)
	if err != nil {
		log.Fatal(err)
	}
	encryptedKey, err = EncryptDecryptBytes(cipherKey, ramCipher, make([]byte, nonceSize), true) // Zero nonce is safe: ramCipher above is freshly random and encrypts this one value exactly once
	if err != nil {
		log.Fatal(err)
	}
}

func getMasterCipher() []byte {
	mu.Lock()
	ek, rc := encryptedKey, ramCipher
	mu.Unlock()
	key, err := EncryptDecryptBytes(ek, rc, make([]byte, nonceSize), false) // Zero nonce: decrypts the single value storeMasterKey encrypted with this same ramCipher
	if err != nil {
		key = []byte{}
		log.Fatal(err)
	}
	return key
}

// Encrypt encrypts a file
func Encrypt(encInfo *models.EncryptionInfo, input io.Reader, output io.Writer) error {
	key, err := generateNewFileKey(encInfo)
	if err != nil {
		return err
	}
	stream := getStream(key)
	// Zero nonce is safe only as long as a given key is ever paired with exactly one
	// distinct plaintext. generateNewFileKey draws a fresh key here on every call, so
	// that holds today (see TestEncryptGeneratesFreshKeyPerCall). The storage layer's
	// dedup path (copyEncryptionInfo) reuses an existing key for identical plaintext,
	// which is still safe - it never calls Encrypt again for that content. What would be
	// catastrophic is a key covering two *different* plaintexts, e.g. a change that fed
	// new content through an existing key instead of a fresh one.
	nonce := make([]byte, stream.NonceSize())
	reader := stream.EncryptReader(input, nonce, nil)
	_, err = io.Copy(output, reader)
	return err
}

func createDecryptReader(encInfo models.EncryptionInfo, input io.Reader) (*sio.DecReader, error) {
	key, err := GetCipherFromFile(encInfo)
	if err != nil {
		return nil, err
	}
	stream := getStream(key)
	nonce := make([]byte, stream.NonceSize()) // Zero nonce mirrors Encrypt; this key was only ever paired with the one plaintext it encrypted
	return stream.DecryptReader(input, nonce, nil), nil
}

// DecryptReader modifies a reader so it can decrypt encrypted files
func DecryptReader(encInfo models.EncryptionInfo, input io.Reader, output io.Writer) error {
	reader, err := createDecryptReader(encInfo, input)
	if err != nil {
		return err
	}
	_, err = io.Copy(output, reader)
	return err
}

// IsCorrectKey checks if the correct key is being used. This does not check for complete file authentication.
func IsCorrectKey(encInfo models.EncryptionInfo, input *os.File) bool {
	_, err := createDecryptReader(encInfo, input)
	if err != nil {
		fmt.Println(err)
		return false
	}
	return true
}

// GetDecryptWriter returns a writer that can decrypt encrypted files
func GetDecryptWriter(cipherKey []byte, input io.Writer) (io.Writer, error) {
	stream := getStream(cipherKey)
	nonce := make([]byte, stream.NonceSize()) // Zero nonce: safe iff caller supplies a key never paired with more than one distinct plaintext (same invariant as Encrypt)
	return stream.DecryptWriter(input, nonce, nil), nil
}

// GetDecryptReader returns a reader that can decrypt encrypted files
func GetDecryptReader(cipherKey []byte, input io.Reader) (io.Reader, error) {
	stream := getStream(cipherKey)
	nonce := make([]byte, stream.NonceSize()) // Zero nonce: safe iff caller supplies a key never paired with more than one distinct plaintext (same invariant as Encrypt)
	return stream.DecryptReader(input, nonce, nil), nil
}

// GetEncryptReader returns a reader that can encrypt plain files
func GetEncryptReader(cipherKey []byte, input io.Reader) (io.Reader, error) {
	stream := getStream(cipherKey)
	nonce := make([]byte, stream.NonceSize()) // Zero nonce: safe iff caller supplies a key never paired with more than one distinct plaintext (same invariant as Encrypt)
	return stream.EncryptReader(input, nonce, nil), nil
}

// GetEncryptWriter returns a writer that can encrypt plain files
func GetEncryptWriter(cipherKey []byte, input io.Writer) (*sio.EncWriter, error) {
	stream := getStream(cipherKey)
	nonce := make([]byte, stream.NonceSize()) // Zero nonce: safe iff caller supplies a key never paired with more than one distinct plaintext (same invariant as Encrypt)
	return stream.EncryptWriter(input, nonce, nil), nil

}

// ErrMasterKeyUnavailable is returned by EncryptString/DecryptString when the server master key
// has not been loaded into memory (see IsDecryptionAvailable) - e.g. encryption is disabled, or
// the instance is configured for end-to-end encryption, where the server never holds a key
// capable of decrypting anything itself.
var ErrMasterKeyUnavailable = errors.New("master key not available")

// EncryptString encrypts an arbitrary plaintext string with the server master key, using
// AES-GCM with a fresh random nonce prepended to the returned ciphertext. Unlike the
// zero-nonce helpers above (safe only because each is paired with a freshly generated,
// single-use file key), this is called repeatedly against the one long-lived master key, so a
// random nonce is required on every call. Returns ErrMasterKeyUnavailable if the master key
// has not been loaded (see IsDecryptionAvailable).
func EncryptString(plaintext string) ([]byte, error) {
	if !IsDecryptionAvailable() {
		return nil, ErrMasterKeyUnavailable
	}
	nonce, err := getRandomData(nonceSize)
	if err != nil {
		return nil, err
	}
	cipherText, err := EncryptDecryptBytes([]byte(plaintext), getMasterCipher(), nonce, true)
	if err != nil {
		return nil, err
	}
	return append(nonce, cipherText...), nil
}

// DecryptString reverses EncryptString. Returns ErrMasterKeyUnavailable if the master key has
// not been loaded (see IsDecryptionAvailable).
func DecryptString(data []byte) (string, error) {
	if !IsDecryptionAvailable() {
		return "", ErrMasterKeyUnavailable
	}
	if len(data) < nonceSize {
		return "", errors.New("encrypted data is shorter than the nonce size")
	}
	nonce := data[:nonceSize]
	cipherText := data[nonceSize:]
	plainBytes, err := EncryptDecryptBytes(cipherText, getMasterCipher(), nonce, false)
	if err != nil {
		return "", err
	}
	return string(plainBytes), nil
}

func generateNewFileKey(encInfo *models.EncryptionInfo) ([]byte, error) {
	encryptionKey, err := getRandomData(blockSize)
	if err != nil {
		return []byte{}, err
	}
	nonce, err := getRandomData(nonceSize)
	if err != nil {
		return []byte{}, err
	}
	encInfo.Nonce = nonce
	encInfo.IsEncrypted = true
	encKey, err := fileCipherEncrypt(encryptionKey, nonce)
	if err != nil {
		return []byte{}, err
	}
	encInfo.DecryptionKey = encKey
	return encryptionKey, nil
}

// CalculateEncryptedFilesize returns the filesize of the encrypted file including the encryption overhead
func CalculateEncryptedFilesize(size int64) int64 {
	return size + getStream(make([]byte, blockSize)).Overhead(size)
}

// GetCipherFromFile loads the cipher from a file model
func GetCipherFromFile(encInfo models.EncryptionInfo) ([]byte, error) {
	cipherFile, err := fileCipherDecrypt(encInfo.DecryptionKey, encInfo.Nonce)
	if err != nil {
		return []byte{}, err
	}
	return cipherFile, nil
}

func getStream(cipherKey []byte) *sio.Stream {
	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		log.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}
	stream := sio.NewStream(gcm, sio.BufSize)
	return stream
}

// fileCipherEncrypt and fileCipherDecrypt are the sole callers of getMasterCipher, and therefore
// the choke point every other function in this package (Encrypt, DecryptReader, GetCipherFromFile,
// IsCorrectKey, generateNewFileKey, ...) funnels through to touch the master key. Checking
// IsSealed here - rather than relying on every call site above to remember to check it - is what
// makes it safe for the storage/webserver layers to gate uploads and downloads without also
// having to prove they covered every path into this package: even a path that forgot to check
// IsSealed itself fails cleanly with ErrSealed here instead of reaching getMasterCipher with no
// key loaded, which would otherwise be a fatal error.
func fileCipherEncrypt(input, nonce []byte) ([]byte, error) {
	if IsSealed() {
		return nil, ErrSealed
	}
	return EncryptDecryptBytes(input, getMasterCipher(), nonce, true)
}
func fileCipherDecrypt(input, nonce []byte) ([]byte, error) {
	if IsSealed() {
		return nil, ErrSealed
	}
	return EncryptDecryptBytes(input, getMasterCipher(), nonce, false)
}

// EncryptDecryptBytes encrypts or decrypts a byte array
func EncryptDecryptBytes(input, cipherBlock, nonce []byte, doEncrypt bool) ([]byte, error) {
	block, err := aes.NewCipher(cipherBlock)
	if err != nil {
		return []byte{}, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return []byte{}, err
	}
	if doEncrypt {
		return aesgcm.Seal(nil, nonce, input, nil), nil
	}
	return aesgcm.Open(nil, nonce, input, nil)
}

func getRandomData(size int) ([]byte, error) {
	data := make([]byte, size)
	read, err := rand.Read(data)
	if err != nil {
		return []byte{}, err
	}
	if read != size {
		return []byte{}, errors.New("incorrect size written")
	}
	return data, nil
}

// GetRandomCipher a 32 byte long array with random data
func GetRandomCipher() ([]byte, error) {
	return getRandomData(blockSize)
}

// GetRandomNonce a 12 byte long array with random data
func GetRandomNonce() ([]byte, error) {
	return getRandomData(nonceSize)
}
