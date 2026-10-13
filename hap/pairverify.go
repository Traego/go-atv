package hap

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
)

// PairVerify is our side of pair-verify, which every connection after
// pairing starts with. Both sides prove they hold the long-term keys from
// pairing and agree a fresh shared secret; SessionKeys derives the session
// cipher's keys from it.
type PairVerify struct {
	creds  Credentials
	priv   *ecdh.PrivateKey
	shared []byte
}

// NewPairVerify starts a verification with the credentials from pairing.
func NewPairVerify(creds Credentials) (*PairVerify, error) {
	if err := creds.Valid(); err != nil {
		return nil, err
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &PairVerify{creds: creds, priv: priv}, nil
}

// M1 sends our ephemeral public key.
func (v *PairVerify) M1() []byte {
	return EncodeTLV8(Item{TLVState, []byte{1}}, Item{TLVPublicKey, v.priv.PublicKey().Bytes()})
}

// M3 checks the device's proof in M2 and returns ours.
func (v *PairVerify) M3(m2 []byte) ([]byte, error) {
	tlv, err := DecodeTLV8(m2)
	if err != nil {
		return nil, err
	}
	if err := TLVErrorOf(tlv); err != nil {
		return nil, err
	}
	if s := stateOf(tlv); s != 2 {
		return nil, fmt.Errorf("hap: expected M2, got state %d", s)
	}
	devicePub, err := need(tlv, TLVPublicKey, "device public key")
	if err != nil {
		return nil, err
	}
	sealed, err := need(tlv, TLVEncryptedData, "encrypted data")
	if err != nil {
		return nil, err
	}
	remote, err := ecdh.X25519().NewPublicKey(devicePub)
	if err != nil {
		return nil, fmt.Errorf("hap: device public key: %w", err)
	}
	v.shared, err = v.priv.ECDH(remote)
	if err != nil {
		return nil, err
	}
	sessionKey := deriveKey(v.shared, "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info")
	plain, err := open(sessionKey, "PV-Msg02", sealed)
	if err != nil {
		return nil, err
	}
	inner, err := DecodeTLV8(plain)
	if err != nil {
		return nil, err
	}
	id, err := need(inner, TLVIdentifier, "device identifier")
	if err != nil {
		return nil, err
	}
	sig, err := need(inner, TLVSignature, "device signature")
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(id, v.creds.DeviceID) {
		return nil, errors.New("hap: a different device answered")
	}
	ourPub := v.priv.PublicKey().Bytes()
	if !ed25519.Verify(ed25519.PublicKey(v.creds.LTPK), concat(devicePub, id, ourPub), sig) {
		return nil, errors.New("hap: device signature is wrong; the pairing may have been removed")
	}
	ltsk := ed25519.NewKeyFromSeed(v.creds.LTSK)
	ourSig := ed25519.Sign(ltsk, concat(ourPub, v.creds.ClientID, devicePub))
	reply := EncodeTLV8(Item{TLVIdentifier, v.creds.ClientID}, Item{TLVSignature, ourSig})
	return EncodeTLV8(Item{TLVState, []byte{3}}, Item{TLVEncryptedData, seal(sessionKey, "PV-Msg03", reply)}), nil
}

// Finish checks M4, the device's acceptance.
func (v *PairVerify) Finish(m4 []byte) error {
	if v.shared == nil {
		return errors.New("hap: Finish before M3")
	}
	tlv, err := DecodeTLV8(m4)
	if err != nil {
		return err
	}
	if err := TLVErrorOf(tlv); err != nil {
		return err
	}
	if s := stateOf(tlv); s != 4 {
		return fmt.Errorf("hap: expected M4, got state %d", s)
	}
	return nil
}

// SessionKeys derives the session cipher's keys from the shared secret: the
// output key for what we send and the input key for what we receive. Each
// protocol has its own salt and info strings. M3 must have run.
func (v *PairVerify) SessionKeys(salt, outputInfo, inputInfo string) (output, input []byte) {
	return deriveKey(v.shared, salt, outputInfo), deriveKey(v.shared, salt, inputInfo)
}
