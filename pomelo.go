package pomelo

import (
	"errors"
	"fmt"
	"time"
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
