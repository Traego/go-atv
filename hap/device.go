package hap

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
)

// The device side of pairing. A real Apple TV is always the device; these
// exist so a test server can stand in for one and so both sides of the
// protocol are checked against each other.

// ErrAuthentication is returned with the reply when the other side failed to
// prove itself; the reply still has to be sent.
var ErrAuthentication = errors.New("hap: authentication failed")

// PairSetupDevice is the device side of pair-setup.
type PairSetupDevice struct {
	pin        string
	id         []byte
	ltsk       ed25519.PrivateKey
	srp        *SRPServer
	sessionKey []byte
}

// NewPairSetupDevice makes a device that accepts pin and identifies itself
// with id and the long-term key ltsk.
func NewPairSetupDevice(pin string, id []byte, ltsk ed25519.PrivateKey) (*PairSetupDevice, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	srp, err := NewSRPServer(SRPUsername, pin, salt)
	if err != nil {
		return nil, err
	}
	return &PairSetupDevice{pin: pin, id: id, ltsk: ltsk, srp: srp}, nil
}

// M2 answers M1 with the salt and the SRP public value.
func (d *PairSetupDevice) M2(m1 []byte) ([]byte, error) {
	tlv, err := DecodeTLV8(m1)
	if err != nil {
		return nil, err
	}
	if s := stateOf(tlv); s != 1 {
		return nil, fmt.Errorf("hap: expected M1, got state %d", s)
	}
	return EncodeTLV8(
		Item{TLVState, []byte{2}},
		Item{TLVSalt, d.srp.Salt()},
		Item{TLVPublicKey, d.srp.Public()},
	), nil
}

// M4 checks the client's proof from M3. A wrong PIN gives an error reply
// and ErrAuthentication; the reply must still be sent.
func (d *PairSetupDevice) M4(m3 []byte) ([]byte, error) {
	tlv, err := DecodeTLV8(m3)
	if err != nil {
		return nil, err
	}
	if s := stateOf(tlv); s != 3 {
		return nil, fmt.Errorf("hap: expected M3, got state %d", s)
	}
	pub, err := need(tlv, TLVPublicKey, "SRP public value")
	if err != nil {
		return nil, err
	}
	proof, err := need(tlv, TLVProof, "proof")
	if err != nil {
		return nil, err
	}
	if err := d.srp.SetClient(pub, proof); err != nil {
		reply := EncodeTLV8(Item{TLVState, []byte{4}}, Item{TLVError, []byte{ErrorAuthentication}})
		return reply, ErrAuthentication
	}
	return EncodeTLV8(Item{TLVState, []byte{4}}, Item{TLVProof, d.srp.Proof()}), nil
}

// Pairing is what the device learns about a client in pair-setup.
type Pairing struct {
	// ClientID is the client's pairing identifier.
	ClientID []byte
	// LTPK is the client's long-term Ed25519 public key.
	LTPK []byte
	// Extra is everything else the client put in its sealed TLV8, such as
	// a name under TLVName.
	Extra map[uint8][]byte
}

// M6 opens M5, checks the client's signature, and answers with the device's
// own identifier and key, signed. extra items go into the sealed reply.
func (d *PairSetupDevice) M6(m5 []byte, extra ...Item) ([]byte, Pairing, error) {
	if d.srp.SessionKey() == nil {
		return nil, Pairing{}, errors.New("hap: M6 before M4")
	}
	tlv, err := DecodeTLV8(m5)
	if err != nil {
		return nil, Pairing{}, err
	}
	if s := stateOf(tlv); s != 5 {
		return nil, Pairing{}, fmt.Errorf("hap: expected M5, got state %d", s)
	}
	sealed, err := need(tlv, TLVEncryptedData, "encrypted data")
	if err != nil {
		return nil, Pairing{}, err
	}
	key := d.srp.SessionKey()
	d.sessionKey = deriveKey(key, "Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info")
	plain, err := open(d.sessionKey, "PS-Msg05", sealed)
	if err != nil {
		return nil, Pairing{}, err
	}
	inner, err := DecodeTLV8(plain)
	if err != nil {
		return nil, Pairing{}, err
	}
	clientID, err := need(inner, TLVIdentifier, "client identifier")
	if err != nil {
		return nil, Pairing{}, err
	}
	ltpk, err := need(inner, TLVPublicKey, "client public key")
	if err != nil {
		return nil, Pairing{}, err
	}
	sig, err := need(inner, TLVSignature, "client signature")
	if err != nil {
		return nil, Pairing{}, err
	}
	controllerX := deriveKey(key, "Pair-Setup-Controller-Sign-Salt", "Pair-Setup-Controller-Sign-Info")
	if len(ltpk) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(ltpk), concat(controllerX, clientID, ltpk), sig) {
		return nil, Pairing{}, ErrAuthentication
	}
	pairing := Pairing{ClientID: clientID, LTPK: ltpk, Extra: inner}

	accessoryX := deriveKey(key, "Pair-Setup-Accessory-Sign-Salt", "Pair-Setup-Accessory-Sign-Info")
	devicePub := d.ltsk.Public().(ed25519.PublicKey)
	items := append([]Item{
		{TLVIdentifier, d.id},
		{TLVPublicKey, devicePub},
		{TLVSignature, ed25519.Sign(d.ltsk, concat(accessoryX, d.id, devicePub))},
	}, extra...)
	reply := EncodeTLV8(Item{TLVState, []byte{6}}, Item{TLVEncryptedData, seal(d.sessionKey, "PS-Msg06", EncodeTLV8(items...))})
	return reply, pairing, nil
}

// PairVerifyDevice is the device side of pair-verify.
type PairVerifyDevice struct {
	id     []byte
	ltsk   ed25519.PrivateKey
	lookup func(clientID []byte) (ltpk []byte, ok bool)
	shared []byte
	key    []byte
	ours   []byte
	theirs []byte
}

// NewPairVerifyDevice makes a device with identifier id and long-term key
// ltsk. lookup returns the long-term public key of a paired client.
func NewPairVerifyDevice(id []byte, ltsk ed25519.PrivateKey, lookup func(clientID []byte) ([]byte, bool)) *PairVerifyDevice {
	return &PairVerifyDevice{id: id, ltsk: ltsk, lookup: lookup}
}

// M2 answers the client's ephemeral key with ours and a signature over
// both.
func (d *PairVerifyDevice) M2(m1 []byte) ([]byte, error) {
	tlv, err := DecodeTLV8(m1)
	if err != nil {
		return nil, err
	}
	if s := stateOf(tlv); s != 1 {
		return nil, fmt.Errorf("hap: expected M1, got state %d", s)
	}
	clientPub, err := need(tlv, TLVPublicKey, "client public key")
	if err != nil {
		return nil, err
	}
	priv, err := x25519Generate()
	if err != nil {
		return nil, err
	}
	d.shared, err = x25519Shared(priv, clientPub)
	if err != nil {
		return nil, err
	}
	d.ours = priv.PublicKey().Bytes()
	d.theirs = clientPub
	d.key = deriveKey(d.shared, "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info")
	sig := ed25519.Sign(d.ltsk, concat(d.ours, d.id, clientPub))
	inner := EncodeTLV8(Item{TLVIdentifier, d.id}, Item{TLVSignature, sig})
	return EncodeTLV8(
		Item{TLVState, []byte{2}},
		Item{TLVPublicKey, d.ours},
		Item{TLVEncryptedData, seal(d.key, "PV-Msg02", inner)},
	), nil
}

// M4 checks the client's signature from M3. An unknown client or a bad
// signature gives an error reply and ErrAuthentication; the reply must
// still be sent.
func (d *PairVerifyDevice) M4(m3 []byte) ([]byte, error) {
	if d.shared == nil {
		return nil, errors.New("hap: M4 before M2")
	}
	fail := EncodeTLV8(Item{TLVState, []byte{4}}, Item{TLVError, []byte{ErrorAuthentication}})
	tlv, err := DecodeTLV8(m3)
	if err != nil {
		return nil, err
	}
	if s := stateOf(tlv); s != 3 {
		return nil, fmt.Errorf("hap: expected M3, got state %d", s)
	}
	sealed, err := need(tlv, TLVEncryptedData, "encrypted data")
	if err != nil {
		return nil, err
	}
	plain, err := open(d.key, "PV-Msg03", sealed)
	if err != nil {
		return fail, ErrAuthentication
	}
	inner, err := DecodeTLV8(plain)
	if err != nil {
		return nil, err
	}
	clientID, sig := inner[TLVIdentifier], inner[TLVSignature]
	ltpk, ok := d.lookup(clientID)
	if !ok || len(ltpk) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(ltpk), concat(d.theirs, clientID, d.ours), sig) {
		return fail, ErrAuthentication
	}
	return EncodeTLV8(Item{TLVState, []byte{4}}), nil
}

// SessionKeys derives the session cipher's keys from the device's point of
// view. The salt and info strings are the same ones the client passes to
// PairVerify.SessionKeys: outputInfo names the key the client sends with,
// so here it is the input key, and the other way round.
func (d *PairVerifyDevice) SessionKeys(salt, outputInfo, inputInfo string) (output, input []byte) {
	return deriveKey(d.shared, salt, inputInfo), deriveKey(d.shared, salt, outputInfo)
}
