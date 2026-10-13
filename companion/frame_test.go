package companion

import (
	"bytes"
	"io"
	"testing"

	"github.com/traego/go-atv/hap"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, Frame{Type: FrameEOpack, Payload: []byte("abc")}, nil); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), []byte{8, 0, 0, 3, 'a', 'b', 'c'}) {
		t.Fatalf("wire %x", buf.Bytes())
	}
	f, err := ReadFrame(&buf, nil)
	if err != nil || f.Type != FrameEOpack || string(f.Payload) != "abc" {
		t.Fatalf("read %v %v", f, err)
	}
}

func TestFrameEncryption(t *testing.T) {
	key1, key2 := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	sender, _ := hap.NewSessionCipher(key1, key2)
	receiver, _ := hap.NewSessionCipher(key2, key1)
	var buf bytes.Buffer
	if err := WriteFrame(&buf, Frame{Type: FrameEOpack, Payload: []byte("abc")}, sender); err != nil {
		t.Fatal(err)
	}
	// The length counts the tag; the header is bound as associated data.
	if got := buf.Bytes()[:4]; !bytes.Equal(got, []byte{8, 0, 0, 3 + hap.Overhead}) {
		t.Fatalf("header %x", got)
	}
	tampered := append([]byte(nil), buf.Bytes()...)
	tampered[0] = byte(FrameUOpack)
	if _, err := ReadFrame(bytes.NewReader(tampered), receiver); err == nil {
		t.Fatal("tampered header accepted")
	}
	receiver, _ = hap.NewSessionCipher(key2, key1)
	f, err := ReadFrame(&buf, receiver)
	if err != nil || string(f.Payload) != "abc" {
		t.Fatalf("read %v %v", f, err)
	}
	// An empty payload is sent in the clear.
	buf.Reset()
	if err := WriteFrame(&buf, Frame{Type: FrameNoOp}, sender); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), []byte{1, 0, 0, 0}) {
		t.Fatalf("empty frame %x", buf.Bytes())
	}
}

func TestReadFrameShort(t *testing.T) {
	if _, err := ReadFrame(bytes.NewReader([]byte{8, 0, 0, 5, 'a'}), nil); err != io.ErrUnexpectedEOF {
		t.Fatalf("got %v", err)
	}
	if _, err := ReadFrame(bytes.NewReader(nil), nil); err != io.EOF {
		t.Fatalf("got %v", err)
	}
}
