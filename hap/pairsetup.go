package hap

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
)

// PairSetup is our side of pair-setup, the one-time exchange that turns the
// PIN a device shows into Credentials. The six messages run in order: we
// send M1, the device answers M2, and so on to M6. Each method takes the
// device's message and returns ours.
type PairSetup struct {
	clientID     []byte
	ltsk         ed25519.PrivateKey
	srp          *SRPClient
	sessionKey   []byte
	accessorySig bool
}

// NewPairSetup makes a new long-term key and client identifier for the
// pairing. The identifier is a UUID in upper-case text, as Apple's own
// clients use.
func NewPairSetup() (*PairSetup, error) {
	_, ltsk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	id, err := newUUIDString()
	if err != nil {
		return nil, err
	}
	return &PairSetup{clientID: []byte(id), ltsk: ltsk}, nil
}

func newUUIDString() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return strings.ToUpper(fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])), nil
}

// ClientID is the identifier this pairing will be known by.
func (p *PairSetup) ClientID() []byte { return p.clientID }

// M1 starts pairing. The device shows its PIN when it receives it.
func (p *PairSetup) M1() []byte {
	return EncodeTLV8(Item{TLVMethod, []byte{MethodPairSetup}}, Item{TLVState, []byte{1}})
}

// M3 takes the device's salt and SRP public value from M2 and proves the
// PIN.
func (p *PairSetup) M3(m2 []byte, pin string) ([]byte, error) {
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
	salt, err := need(tlv, TLVSalt, "salt")
	if err != nil {
		return nil, err
	}
	pub, err := need(tlv, TLVPublicKey, "SRP public value")
	if err != nil {
		return nil, err
	}
	p.srp, err = NewSRPClient(SRPUsername, pin)
	if err != nil {
		return nil, err
	}
	if err := p.srp.SetServer(salt, pub); err != nil {
		return nil, err
	}
	return EncodeTLV8(
		Item{TLVState, []byte{3}},
		Item{TLVPublicKey, p.srp.Public()},
		Item{TLVProof, p.srp.Proof()},
	), nil
}

// M5 checks the device's proof from M4 and sends our long-term public key,
// signed, under the session key. extra items go into the same sealed TLV8;
// Companion adds a TLVName there.
func (p *PairSetup) M5(m4 []byte, extra ...Item) ([]byte, error) {
	if p.srp == nil {
		return nil, errors.New("hap: M5 before M3")
	}
	tlv, err := DecodeTLV8(m4)
	if err != nil {
		return nil, err
	}
	if err := TLVErrorOf(tlv); err != nil {
		return nil, err
	}
	if s := stateOf(tlv); s != 4 {
		return nil, fmt.Errorf("hap: expected M4, got state %d", s)
	}
	proof, err := need(tlv, TLVProof, "proof")
	if err != nil {
		return nil, err
	}
	if !p.srp.VerifyServerProof(proof) {
		return nil, errors.New("hap: device proof is wrong")
	}
	key := p.srp.SessionKey()
	signingKey := deriveKey(key, "Pair-Setup-Controller-Sign-Salt", "Pair-Setup-Controller-Sign-Info")
	p.sessionKey = deriveKey(key, "Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info")
	ltpk := p.ltsk.Public().(ed25519.PublicKey)
	info := concat(signingKey, p.clientID, ltpk)
	items := append([]Item{
		{TLVIdentifier, p.clientID},
		{TLVPublicKey, ltpk},
		{TLVSignature, ed25519.Sign(p.ltsk, info)},
	}, extra...)
	sealed := seal(p.sessionKey, "PS-Msg05", EncodeTLV8(items...))
	return EncodeTLV8(Item{TLVState, []byte{5}}, Item{TLVEncryptedData, sealed}), nil
}

// Finish opens M6, which carries the device's identifier and long-term
// public key, and returns the credentials along with everything else the
// device put in the sealed TLV8, such as its name under TLVName.
//
// The device's signature in M6 is not checked, as pyatv does not check it.
// M6 is sealed under a key only a holder of the PIN can derive, so the
// signature adds nothing a reader of this port depends on.
func (p *PairSetup) Finish(m6 []byte) (Credentials, map[uint8][]byte, error) {
	if p.sessionKey == nil {
		return Credentials{}, nil, errors.New("hap: Finish before M5")
	}
	tlv, err := DecodeTLV8(m6)
	if err != nil {
		return Credentials{}, nil, err
	}
	if err := TLVErrorOf(tlv); err != nil {
		return Credentials{}, nil, err
	}
	if s := stateOf(tlv); s != 6 {
		return Credentials{}, nil, fmt.Errorf("hap: expected M6, got state %d", s)
	}
	sealed, err := need(tlv, TLVEncryptedData, "encrypted data")
	if err != nil {
		return Credentials{}, nil, err
	}
	plain, err := open(p.sessionKey, "PS-Msg06", sealed)
	if err != nil {
		return Credentials{}, nil, err
	}
	inner, err := DecodeTLV8(plain)
	if err != nil {
		return Credentials{}, nil, err
	}
	id, err := need(inner, TLVIdentifier, "device identifier")
	if err != nil {
		return Credentials{}, nil, err
	}
	ltpk, err := need(inner, TLVPublicKey, "device public key")
	if err != nil {
		return Credentials{}, nil, err
	}
	creds := Credentials{
		LTPK:     ltpk,
		LTSK:     p.ltsk.Seed(),
		DeviceID: id,
		ClientID: p.clientID,
	}
	if err := creds.Valid(); err != nil {
		return Credentials{}, nil, err
	}
	return creds, inner, nil
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
