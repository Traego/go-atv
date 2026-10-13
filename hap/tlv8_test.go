package hap

import (
	"bytes"
	"testing"
)

func TestTLV8RoundTrip(t *testing.T) {
	long := bytes.Repeat([]byte{0xab}, 300)
	enc := EncodeTLV8(
		Item{TLVState, []byte{1}},
		Item{TLVPublicKey, long},
		Item{TLVMethod, nil},
	)
	// 300 bytes split into 255 and 45.
	want := append([]byte{TLVState, 1, 1, TLVPublicKey, 255}, long[:255]...)
	want = append(want, TLVPublicKey, 45)
	want = append(want, long[255:]...)
	want = append(want, TLVMethod, 0)
	if !bytes.Equal(enc, want) {
		t.Fatalf("encoded %x, want %x", enc, want)
	}
	dec, err := DecodeTLV8(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec[TLVPublicKey], long) {
		t.Fatalf("long value not joined back: %d bytes", len(dec[TLVPublicKey]))
	}
	if !bytes.Equal(dec[TLVState], []byte{1}) || len(dec[TLVMethod]) != 0 {
		t.Fatalf("decoded %v", dec)
	}
}

func TestDecodeTLV8Truncated(t *testing.T) {
	for _, data := range [][]byte{{TLVState}, {TLVState, 2, 1}} {
		if _, err := DecodeTLV8(data); err == nil {
			t.Errorf("%x: want error", data)
		}
	}
}

func TestTLVErrorOf(t *testing.T) {
	tlv, _ := DecodeTLV8(EncodeTLV8(Item{TLVState, []byte{4}}, Item{TLVError, []byte{ErrorAuthentication}}))
	err := TLVErrorOf(tlv)
	if err == nil || err.Error() != "hap: device said authentication failed" {
		t.Fatalf("got %v", err)
	}
	if TLVErrorOf(map[uint8][]byte{}) != nil {
		t.Fatal("no error expected")
	}
}
