package hap

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Credentials is what pairing produces and what every later connection
// presents. It is a pair of long-term keys and the identifiers each side
// chose. The String form is pyatv's, four hex fields joined by colons, so a
// pairing made with either implementation works with the other.
type Credentials struct {
	// LTPK is the device's long-term Ed25519 public key.
	LTPK []byte
	// LTSK is our long-term Ed25519 private key, as a 32-byte seed.
	LTSK []byte
	// DeviceID is the device's pairing identifier, usually a UUID in text.
	DeviceID []byte
	// ClientID is our pairing identifier, a UUID in text.
	ClientID []byte
}

// String encodes the credentials as ltpk:ltsk:device_id:client_id in hex.
func (c Credentials) String() string {
	return strings.Join([]string{
		hex.EncodeToString(c.LTPK),
		hex.EncodeToString(c.LTSK),
		hex.EncodeToString(c.DeviceID),
		hex.EncodeToString(c.ClientID),
	}, ":")
}

// Valid reports whether the credentials are complete and the keys have the
// right sizes.
func (c Credentials) Valid() error {
	if len(c.LTPK) != ed25519.PublicKeySize {
		return fmt.Errorf("hap: device public key is %d bytes, want %d", len(c.LTPK), ed25519.PublicKeySize)
	}
	if len(c.LTSK) != ed25519.SeedSize {
		return fmt.Errorf("hap: private key seed is %d bytes, want %d", len(c.LTSK), ed25519.SeedSize)
	}
	if len(c.DeviceID) == 0 || len(c.ClientID) == 0 {
		return errors.New("hap: credentials are missing an identifier")
	}
	return nil
}

// ParseCredentials decodes the String form.
func ParseCredentials(s string) (Credentials, error) {
	parts := strings.Split(strings.TrimSpace(s), ":")
	if len(parts) != 4 {
		return Credentials{}, errors.New("hap: credentials want four colon-separated hex fields")
	}
	var fields [4][]byte
	for i, p := range parts {
		b, err := hex.DecodeString(p)
		if err != nil {
			return Credentials{}, fmt.Errorf("hap: credentials field %d: %w", i+1, err)
		}
		fields[i] = b
	}
	c := Credentials{LTPK: fields[0], LTSK: fields[1], DeviceID: fields[2], ClientID: fields[3]}
	if err := c.Valid(); err != nil {
		return Credentials{}, err
	}
	return c, nil
}
