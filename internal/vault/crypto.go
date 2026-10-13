package vault

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/torquemada163/tui-ssh-manager/internal/domain"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const MaxFileSize = 16 << 20

type header struct {
	Version    int    `json:"version"`
	Salt       []byte `json:"salt"`
	Memory     uint32 `json:"memory_kib"`
	Time       uint32 `json:"iterations"`
	Threads    uint8  `json:"threads"`
	WrapNonce  []byte `json:"wrap_nonce"`
	WrappedKey []byte `json:"wrapped_key"`
}

type envelope struct {
	Header     header `json:"header"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

func random(n int) ([]byte, error) { b := make([]byte, n); _, err := rand.Read(b); return b, err }
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (h header) valid() bool {
	return h.Version == 1 && len(h.Salt) == 16 && h.Memory >= 8*1024 && h.Memory <= 128*1024 && h.Time >= 1 && h.Time <= 6 && h.Threads >= 1 && h.Threads <= 4 && len(h.WrapNonce) == 24 && len(h.WrappedKey) == 48
}

func wrapAAD(h header) []byte { h.WrappedKey = nil; b, _ := json.Marshal(h); return b }

func derive(password []byte, h header) []byte {
	return argon2.IDKey(password, h.Salt, h.Time, h.Memory, h.Threads, 32)
}
func rewrap(h *header, kek, key []byte) error {
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return err
	}
	h.WrappedKey = nil
	h.WrappedKey = aead.Seal(nil, h.WrapNonce, key, wrapAAD(*h))
	return nil
}

func newHeader(password []byte) (header, []byte, error) {
	if len(password) < 10 {
		return header{}, nil, errors.New("master password must contain at least 10 bytes")
	}
	salt, err := random(16)
	if err != nil {
		return header{}, nil, err
	}
	nonce, err := random(24)
	if err != nil {
		return header{}, nil, err
	}
	key, err := random(32)
	if err != nil {
		return header{}, nil, err
	}
	h := header{Version: 1, Salt: salt, Memory: 64 * 1024, Time: 3, Threads: 4, WrapNonce: nonce}
	kek := argon2.IDKey(password, h.Salt, h.Time, h.Memory, h.Threads, 32)
	defer wipe(kek)
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		wipe(key)
		return header{}, nil, err
	}
	h.WrappedKey = aead.Seal(nil, nonce, key, wrapAAD(h))
	return h, key, nil
}

func decrypt(raw, password []byte) (domain.Document, header, []byte, error) {
	var env envelope
	if len(raw) > MaxFileSize || json.Unmarshal(raw, &env) != nil || !env.Header.valid() || len(env.Nonce) != 24 {
		return domain.Document{}, header{}, nil, errors.New("invalid or unsupported vault format")
	}
	h := env.Header
	kek := argon2.IDKey(password, h.Salt, h.Time, h.Memory, h.Threads, 32)
	defer wipe(kek)
	wrapper, _ := chacha20poly1305.NewX(kek)
	key, err := wrapper.Open(nil, h.WrapNonce, h.WrappedKey, wrapAAD(h))
	if err != nil {
		return domain.Document{}, header{}, nil, errors.New("incorrect password or damaged vault")
	}
	doc, err := decryptData(env, key)
	if err != nil {
		wipe(key)
		return domain.Document{}, header{}, nil, err
	}
	return doc, h, key, nil
}

func decryptData(env envelope, key []byte) (domain.Document, error) {
	if !env.Header.valid() || len(env.Nonce) != 24 {
		return domain.Document{}, errors.New("invalid vault envelope")
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return domain.Document{}, err
	}
	aad, _ := json.Marshal(env.Header)
	plain, err := aead.Open(nil, env.Nonce, env.Ciphertext, aad)
	if err != nil {
		return domain.Document{}, errors.New("vault integrity check failed or encryption key changed; reopen the vault")
	}
	defer wipe(plain)
	var d domain.Document
	if err := json.Unmarshal(plain, &d); err != nil {
		return d, errors.New("invalid vault contents")
	}
	return d, d.Validate()
}

func encrypt(d domain.Document, h header, key []byte) ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	plain, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	defer wipe(plain)
	if len(plain) > MaxFileSize/2 {
		return nil, fmt.Errorf("vault contents exceed size limit")
	}
	nonce, err := random(24)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	aad, _ := json.Marshal(h)
	return json.Marshal(envelope{Header: h, Nonce: nonce, Ciphertext: aead.Seal(nil, nonce, plain, aad)})
}
