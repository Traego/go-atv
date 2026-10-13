package hap

import (
	"errors"
	"fmt"
)

// The TLV8 types of the pairing specification, plus two Apple uses in its own
// protocols.
const (
	// TLVMethod is the pairing method, see Method*.
	TLVMethod uint8 = 0x00
	// TLVIdentifier is a pairing identifier, ours or the device's.
	TLVIdentifier uint8 = 0x01
	// TLVSalt is the SRP salt.
	TLVSalt uint8 = 0x02
	// TLVPublicKey is an SRP, Ed25519 or X25519 public key, depending on the
	// step.
	TLVPublicKey uint8 = 0x03
	// TLVProof is an SRP proof.
	TLVProof uint8 = 0x04
	// TLVEncryptedData is a ChaCha20-Poly1305 sealed TLV8.
	TLVEncryptedData uint8 = 0x05
	// TLVState is the step number, M1 to M6.
	TLVState uint8 = 0x06
	// TLVError is an error code, see Error*.
	TLVError uint8 = 0x07
	// TLVRetryDelay is the seconds to wait before pairing again.
	TLVRetryDelay uint8 = 0x08
	// TLVCertificate is an MFi certificate; unused here.
	TLVCertificate uint8 = 0x09
	// TLVSignature is an Ed25519 signature.
	TLVSignature uint8 = 0x0A
	// TLVPermissions is the pairing's permissions; unused here.
	TLVPermissions uint8 = 0x0B
	// TLVFragmentData is a fragment of a larger message; unused here.
	TLVFragmentData uint8 = 0x0C
	// TLVFragmentLast is the last fragment; unused here.
	TLVFragmentLast uint8 = 0x0D
	// TLVName carries extra information about a device in Apple's own
	// protocols. Companion packs an OPACK dictionary into it.
	TLVName uint8 = 0x11
	// TLVFlags carries pairing flags, see FlagTransientPairing.
	TLVFlags uint8 = 0x13
)

// The pairing methods.
const (
	MethodPairSetup         uint8 = 0x00
	MethodPairSetupWithAuth uint8 = 0x01
	MethodPairVerify        uint8 = 0x02
	MethodAddPairing        uint8 = 0x03
	MethodRemovePairing     uint8 = 0x04
	MethodListPairings      uint8 = 0x05
)

// The error codes a device can answer with.
const (
	ErrorUnknown        uint8 = 0x01
	ErrorAuthentication uint8 = 0x02
	ErrorBackoff        uint8 = 0x03
	ErrorMaxPeers       uint8 = 0x04
	ErrorMaxTries       uint8 = 0x05
	ErrorUnavailable    uint8 = 0x06
	ErrorBusy           uint8 = 0x07
)

// FlagTransientPairing asks for a pairing that lasts one session; unused by
// Companion.
const FlagTransientPairing uint8 = 0x10

// Item is one TLV8 entry.
type Item struct {
	Type  uint8
	Value []byte
}

// EncodeTLV8 encodes items in order. A value longer than 255 bytes is split
// into consecutive entries of the same type, as the specification says.
func EncodeTLV8(items ...Item) []byte {
	var out []byte
	for _, it := range items {
		v := it.Value
		if len(v) == 0 {
			out = append(out, it.Type, 0)
			continue
		}
		for len(v) > 0 {
			n := min(len(v), 255)
			out = append(out, it.Type, uint8(n))
			out = append(out, v[:n]...)
			v = v[n:]
		}
	}
	return out
}

// DecodeTLV8 decodes data into a map by type. Consecutive entries of one type
// are joined back into one value.
func DecodeTLV8(data []byte) (map[uint8][]byte, error) {
	out := map[uint8][]byte{}
	var last uint8
	first := true
	for pos := 0; pos < len(data); {
		if pos+2 > len(data) {
			return nil, errors.New("hap: truncated TLV8 header")
		}
		t, n := data[pos], int(data[pos+1])
		pos += 2
		if pos+n > len(data) {
			return nil, fmt.Errorf("hap: TLV8 type %#x: want %d bytes, have %d", t, n, len(data)-pos)
		}
		v := data[pos : pos+n]
		pos += n
		if _, seen := out[t]; seen && !(t == last && !first) {
			return nil, fmt.Errorf("hap: TLV8 type %#x repeated out of sequence", t)
		}
		out[t] = append(out[t], v...)
		last, first = t, false
	}
	return out, nil
}

// TLVErrorOf returns the error a device put in its answer, if any.
func TLVErrorOf(tlv map[uint8][]byte) error {
	code, ok := tlv[TLVError]
	if !ok || len(code) == 0 {
		return nil
	}
	return &DeviceError{Code: code[0]}
}

// DeviceError is an error code a device answered with during pairing.
type DeviceError struct {
	Code uint8
}

func (e *DeviceError) Error() string {
	names := map[uint8]string{
		ErrorUnknown:        "unknown",
		ErrorAuthentication: "authentication failed",
		ErrorBackoff:        "back off",
		ErrorMaxPeers:       "too many pairings",
		ErrorMaxTries:       "too many attempts",
		ErrorUnavailable:    "unavailable",
		ErrorBusy:           "busy",
	}
	if n, ok := names[e.Code]; ok {
		return "hap: device said " + n
	}
	return fmt.Sprintf("hap: device error %#x", e.Code)
}

// stateOf returns the step number in a TLV8, or 0.
func stateOf(tlv map[uint8][]byte) uint8 {
	if s := tlv[TLVState]; len(s) > 0 {
		return s[0]
	}
	return 0
}

// need returns the value of a required type.
func need(tlv map[uint8][]byte, t uint8, what string) ([]byte, error) {
	v, ok := tlv[t]
	if !ok {
		return nil, fmt.Errorf("hap: %s missing from device message", what)
	}
	return v, nil
}
