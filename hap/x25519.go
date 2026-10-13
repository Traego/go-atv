package hap

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
)

func x25519Generate() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

func x25519Shared(priv *ecdh.PrivateKey, peer []byte) ([]byte, error) {
	pub, err := ecdh.X25519().NewPublicKey(peer)
	if err != nil {
		return nil, fmt.Errorf("hap: peer public key: %w", err)
	}
	return priv.ECDH(pub)
}
