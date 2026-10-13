package hap

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// deriveKey is HKDF-SHA-512 with a 32-byte output, the derivation every
// pairing key uses.
func deriveKey(secret []byte, salt, info string) []byte {
	key, err := hkdf.Key(sha512.New, secret, []byte(salt), info, 32)
	if err != nil {
		panic("hap: hkdf: " + err.Error())
	}
	return key
}

// labelNonce is the 12-byte nonce for a pairing message: four zero bytes and
// the message's eight-character label, such as "PS-Msg05".
func labelNonce(label string) []byte {
	n := make([]byte, chacha20poly1305.NonceSize)
	copy(n[4:], label)
	return n
}

// seal encrypts a pairing message under key with its label as nonce.
func seal(key []byte, label string, plaintext []byte) []byte {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic("hap: " + err.Error())
	}
	return aead.Seal(nil, labelNonce(label), plaintext, nil)
}

// open decrypts a pairing message sealed by seal.
func open(key []byte, label string, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, labelNonce(label), ciphertext, nil)
	if err != nil {
		return nil, errors.New("hap: cannot decrypt device message")
	}
	return plain, nil
}

// SessionCipher encrypts what we send and decrypts what we receive once a
// session is established. Each direction has its own key and its own
// counter, which is the nonce: 64 bits little-endian followed by four zero
// bytes. It is safe for one goroutine to encrypt while another decrypts.
type SessionCipher struct {
	outMu      sync.Mutex
	out        cipher.AEAD
	outCounter uint64
	inMu       sync.Mutex
	in         cipher.AEAD
	inCounter  uint64
}

// NewSessionCipher makes a cipher from the output key, for what we send, and
// the input key, for what we receive.
func NewSessionCipher(outputKey, inputKey []byte) (*SessionCipher, error) {
	out, err := chacha20poly1305.New(outputKey)
	if err != nil {
		return nil, err
	}
	in, err := chacha20poly1305.New(inputKey)
	if err != nil {
		return nil, err
	}
	return &SessionCipher{out: out, in: in}, nil
}

// Overhead is the bytes the authentication tag adds to a sealed message.
const Overhead = chacha20poly1305.Overhead

// Encrypt seals plaintext with the next output nonce, binding aad.
func (c *SessionCipher) Encrypt(plaintext, aad []byte) []byte {
	c.outMu.Lock()
	defer c.outMu.Unlock()
	nonce := counterNonce(c.outCounter)
	c.outCounter++
	return c.out.Seal(nil, nonce, plaintext, aad)
}

// Decrypt opens ciphertext with the next input nonce, checking aad.
func (c *SessionCipher) Decrypt(ciphertext, aad []byte) ([]byte, error) {
	c.inMu.Lock()
	defer c.inMu.Unlock()
	nonce := counterNonce(c.inCounter)
	c.inCounter++
	plain, err := c.in.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errors.New("hap: cannot decrypt message")
	}
	return plain, nil
}

func counterNonce(counter uint64) []byte {
	n := make([]byte, chacha20poly1305.NonceSize)
	binary.LittleEndian.PutUint64(n, counter)
	return n
}
