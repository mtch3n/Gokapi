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
	"time"

	"github.com/forceu/gokapi/internal/helper"
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

var encryptedKey, ramCipher []byte

// IsDecryptionAvailable returns true if the master encryption key has been
// loaded into memory, meaning server-side decryption is possible.
func IsDecryptionAvailable() bool {
	return len(ramCipher) > 0
}

const blockSize = 32
const nonceSize = 12

// envMasterKey is the name of the environment variable that can supply the master key
// externally, e.g. resolved from a secret store into the environment before startup
const envMasterKey = "GOKAPI_ENCRYPTION_KEY_B64"

// Init needs to be called to load the master key into memory or ask the user for the password
func Init(config models.Configuration) {
	externalKey, err := getExternalKey(config.Encryption.Level)
	if err != nil {
		log.Fatal(err)
	}
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
		initWithPassword(config.Encryption.Salt, config.Encryption.Checksum, config.Encryption.ChecksumSalt)
	case EndToEndEncryption:
		return
	}
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

func initWithPassword(saltPw, expectedChecksum, saltChecksum string) {
	if saltPw == "" || saltChecksum == "" {
		log.Fatal("Empty salt provided. Please rerun setup with --reconfigure")
	}
	pw := readAndCheckPassword(expectedChecksum, saltChecksum)
	cipherKey, err := scrypt.Key([]byte(pw), []byte(saltPw), 1048576, 8, 1, blockSize)
	if err != nil {
		cipherKey = []byte{}
		log.Fatal(err)
	}

	storeMasterKey(cipherKey)
}

func readAndCheckPassword(expectedChecksum, saltChecksum string) string {
	fmt.Println("Please enter encryption password:")
	pw := helper.ReadPassword()
	if pw == "" {
		log.Fatal("Empty password provided")
	}
	fmt.Print("Checking password")

	checksumFinished := false
	go func() {
		for !checksumFinished {
			fmt.Print(".")
			time.Sleep(time.Second)
		}
	}()

	checkSum := PasswordChecksum(pw, saltChecksum)
	checksumFinished = true

	if checkSum != expectedChecksum {
		pw = ""
		fmt.Println("FAIL")
		log.Fatal("Incorrect password provided")
	}

	fmt.Println("OK")
	return pw
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
	key, err := EncryptDecryptBytes(encryptedKey, ramCipher, make([]byte, nonceSize), false) // Zero nonce: decrypts the single value storeMasterKey encrypted with this same ramCipher
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

func fileCipherEncrypt(input, nonce []byte) ([]byte, error) {
	return EncryptDecryptBytes(input, getMasterCipher(), nonce, true)
}
func fileCipherDecrypt(input, nonce []byte) ([]byte, error) {
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
