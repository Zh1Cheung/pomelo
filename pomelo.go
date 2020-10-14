package pomelo

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/eknkc/basex"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	version byte   = 0xBA // Magic byte
	base62  string = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

var (
	ErrInvalidToken        = errors.New("invalid base62 token")
	ErrInvalidTokenVersion = errors.New("invalid token version")
	ErrBadKeyLength        = errors.New("bad key length")
)

type ErrExpiredToken struct {
	Time time.Time
}

func (e *ErrExpiredToken) Error() string {
	delta := time.Unix(time.Now().Unix(), 0).Sub(time.Unix(e.Time.Unix(), 0))
	return fmt.Sprintf("token is expired by %v", delta)
}

// Pomelo holds a key of exactly 32 bytes. The random and timestamp are used for acceptance tests.
type Pomelo struct {
	Key       string
	random    string
	ttl       uint32
	timestamp uint32
}

// SetTTL sets a Time To Live on the token for valid tokens.
func (b *Pomelo) SetTTL(ttl uint32) {
	b.ttl = ttl
}

// setTimeStamp sets a timestamp for testing.
func (b *Pomelo) setTimeStamp(timestamp uint32) {
	b.timestamp = timestamp
}

// setRandom sets a random for testing.
func (b *Pomelo) setRandom(random string) {
	b.random = random
}

// NewPomelo creates a *Pomelo struct.
func NewPomelo(key string) (b *Pomelo) {
	return &Pomelo{
		Key: key,
	}
}

// EncodeToString encodes the data matching the format:
// Version (byte) || Timestamp ([4]byte) || Random ([24]byte) || Ciphertext ([]byte) || Tag ([16]byte)
func (b *Pomelo) EncodeToString(data string) (string, error) {
	var timestamp uint32
	var random []byte
	if b.timestamp == 0 {
		b.timestamp = uint32(time.Now().Unix())
	}
	timestamp = b.timestamp

	if len(b.random) == 0 {
		random = make([]byte, 24)
		if _, err := rand.Read(random); err != nil {
			return "", err
		}
	} else {
		randombytes, err := hex.DecodeString(b.random)
		if err != nil {
			return "", ErrInvalidToken
		}
		random = randombytes
	}

	key := bytes.NewBufferString(b.Key).Bytes()
	payload := bytes.NewBufferString(data).Bytes()

	timeBuffer := make([]byte, 4)
	binary.BigEndian.PutUint32(timeBuffer, timestamp)
	header := append(timeBuffer, random...)
	header = append([]byte{version}, header...)

	xchacha, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", ErrBadKeyLength
	}

	ciphertext := xchacha.Seal(nil, random, payload, header)

	token := append(header, ciphertext...)
	base62, err := basex.NewEncoding(base62)
	if err != nil {
		return "", err
	}
	return base62.Encode(token), nil
}
