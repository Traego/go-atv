package hap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func newDeviceKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// pair runs pair-setup between a client and a device and returns what each
// side learned.
func pair(t *testing.T, pin, entered string, deviceID []byte, deviceKey ed25519.PrivateKey) (Credentials, Pairing, error) {
	t.Helper()
	client, err := NewPairSetup()
	if err != nil {
		t.Fatal(err)
	}
	device, err := NewPairSetupDevice(pin, deviceID, deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	m2, err := device.M2(client.M1())
	if err != nil {
		t.Fatal(err)
	}
	m3, err := client.M3(m2, entered)
	if err != nil {
		t.Fatal(err)
	}
	m4, err := device.M4(m3)
	if err != nil {
		// The reply still goes to the client, which reports the error.
		_, cerr := client.M5(m4)
		return Credentials{}, Pairing{}, errors.Join(err, cerr)
	}
	m5, err := client.M5(m4, Item{TLVName, []byte("my name")})
	if err != nil {
		t.Fatal(err)
	}
	m6, pairing, err := device.M6(m5, Item{TLVName, []byte("Living Room")})
	if err != nil {
		t.Fatal(err)
	}
	creds, extra, err := client.Finish(m6)
	if err != nil {
		t.Fatal(err)
	}
	if string(extra[TLVName]) != "Living Room" {
		t.Errorf("device extra %q", extra[TLVName])
	}
	return creds, pairing, nil
}

func TestPairSetup(t *testing.T) {
	key := newDeviceKey(t)
	creds, pairing, err := pair(t, "1111", "1111", []byte("DEVICE-ID"), key)
	if err != nil {
		t.Fatal(err)
	}
	if string(creds.DeviceID) != "DEVICE-ID" {
		t.Errorf("device id %q", creds.DeviceID)
	}
	if !bytes.Equal(creds.LTPK, key.Public().(ed25519.PublicKey)) {
		t.Error("device public key differs")
	}
	if !bytes.Equal(pairing.ClientID, creds.ClientID) || len(pairing.ClientID) != 36 {
		t.Errorf("client id %q", pairing.ClientID)
	}
	if !bytes.Equal(pairing.LTPK, ed25519.NewKeyFromSeed(creds.LTSK).Public().(ed25519.PublicKey)) {
		t.Error("client public key differs")
	}
	if string(pairing.Extra[TLVName]) != "my name" {
		t.Errorf("client extra %q", pairing.Extra[TLVName])
	}
}

func TestPairSetupWrongPIN(t *testing.T) {
	_, _, err := pair(t, "1111", "9999", []byte("DEVICE-ID"), newDeviceKey(t))
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("device: %v", err)
	}
	var devErr *DeviceError
	if !errors.As(err, &devErr) || devErr.Code != ErrorAuthentication {
		t.Fatalf("client: %v", err)
	}
}

func TestPairSetupStepsOutOfOrder(t *testing.T) {
	client, _ := NewPairSetup()
	if _, err := client.M5(nil); err == nil {
		t.Error("M5 before M3 accepted")
	}
	if _, _, err := client.Finish(nil); err == nil {
		t.Error("Finish before M5 accepted")
	}
	if _, err := client.M3(EncodeTLV8(Item{TLVState, []byte{4}}), "1111"); err == nil {
		t.Error("wrong state accepted")
	}
}

func verify(t *testing.T, creds Credentials, device *PairVerifyDevice) (*PairVerify, error) {
	t.Helper()
	client, err := NewPairVerify(creds)
	if err != nil {
		t.Fatal(err)
	}
	m2, err := device.M2(client.M1())
	if err != nil {
		t.Fatal(err)
	}
	m3, err := client.M3(m2)
	if err != nil {
		return nil, err
	}
	m4, err := device.M4(m3)
	if err != nil {
		if cerr := client.Finish(m4); cerr != nil {
			return nil, errors.Join(err, cerr)
		}
		return nil, err
	}
	return client, client.Finish(m4)
}

func TestPairVerifyAndSession(t *testing.T) {
	key := newDeviceKey(t)
	creds, pairing, err := pair(t, "1111", "1111", []byte("DEVICE-ID"), key)
	if err != nil {
		t.Fatal(err)
	}
	device := NewPairVerifyDevice([]byte("DEVICE-ID"), key, func(id []byte) ([]byte, bool) {
		if bytes.Equal(id, pairing.ClientID) {
			return pairing.LTPK, true
		}
		return nil, false
	})
	client, err := verify(t, creds, device)
	if err != nil {
		t.Fatal(err)
	}
	cOut, cIn := client.SessionKeys("", "ClientEncrypt-main", "ServerEncrypt-main")
	dOut, dIn := device.SessionKeys("", "ClientEncrypt-main", "ServerEncrypt-main")
	if !bytes.Equal(cOut, dIn) || !bytes.Equal(cIn, dOut) || bytes.Equal(cOut, cIn) {
		t.Fatal("session keys do not match up")
	}
	cc, _ := NewSessionCipher(cOut, cIn)
	dc, _ := NewSessionCipher(dOut, dIn)
	for i := 0; i < 3; i++ {
		aad := []byte{8, 0, 0, byte(i)}
		sealed := cc.Encrypt([]byte("hello"), aad)
		if len(sealed) != 5+Overhead {
			t.Fatalf("sealed %d bytes", len(sealed))
		}
		plain, err := dc.Decrypt(sealed, aad)
		if err != nil || string(plain) != "hello" {
			t.Fatalf("round %d: %q %v", i, plain, err)
		}
	}
	// A replayed frame fails because the counter moved on.
	sealed := cc.Encrypt([]byte("x"), nil)
	if _, err := dc.Decrypt(sealed, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := dc.Decrypt(sealed, nil); err == nil {
		t.Fatal("replay accepted")
	}
}

func TestPairVerifyRejectsUnknownClient(t *testing.T) {
	key := newDeviceKey(t)
	creds, _, err := pair(t, "1111", "1111", []byte("DEVICE-ID"), key)
	if err != nil {
		t.Fatal(err)
	}
	device := NewPairVerifyDevice([]byte("DEVICE-ID"), key, func([]byte) ([]byte, bool) { return nil, false })
	_, err = verify(t, creds, device)
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("got %v", err)
	}
}

func TestPairVerifyRejectsWrongDevice(t *testing.T) {
	key := newDeviceKey(t)
	creds, pairing, err := pair(t, "1111", "1111", []byte("DEVICE-ID"), key)
	if err != nil {
		t.Fatal(err)
	}
	lookup := func([]byte) ([]byte, bool) { return pairing.LTPK, true }
	// Same identifier, different key.
	if _, err := verify(t, creds, NewPairVerifyDevice([]byte("DEVICE-ID"), newDeviceKey(t), lookup)); err == nil {
		t.Error("forged device accepted")
	}
	// Different identifier, right key.
	if _, err := verify(t, creds, NewPairVerifyDevice([]byte("OTHER"), key, lookup)); err == nil {
		t.Error("other device accepted")
	}
}
