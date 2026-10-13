package hap

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

// Vectors from srptools, the SRP library pyatv uses, with a = 0xaa..., b =
// 0xbb..., salt 00112233445566778899aabbccddeeff and PIN 1111.
const (
	srpVectorA  = "527b274487f59bd8eefbd84492170ca8674b908b14fa16cb80b59b843fe8f4f78621852e6d3af2eb5ad52f223942e7d3de2352e43a022190f17f2f23c02b6b2af09eae23ed2e52074b73eefefa8573fed184dcea95c99a20d01046dbffe5fd17d3a8c7616de49a10b990183111c8b2032386cec4ec5c3e8d70ca7696d3cea2c2a9ab970c22e9706ee34f7ffff1a0d4af09605dc1814fd4ee6dbea2d430b6a25fe47bffbe221a95db81bdbc0a213d263c5e13e10c89e9d3f46155a3f3b944064c819376140a09b61a2f4e62c21665e4d4e2b991f92a23720888e72726456d6b3f79805532cef564307c7d119e05d06572387109d46d88008419ad80a4da83f6fa5a25b1e955b7dd14bb06fbbc54553cd955174c5df33eb1e540f00389a06f0e9a2ceec8fd1c67bc750d3abbdacf39b75194fbb35a36c9a1657539ca7d82dbcb5aa25bf45f8ca78ae894fdbf30feaf6ad4e1a97a57a86f4f0cd46b22b0c4e74ff42a5c65143a2f91043e00ad29c60094526cac43354c4895bbcdcc5a0db12818c3"
	srpVectorB  = "a9988092970e41d109302a1cab5162b9be911fabba9505a435790cc2b051afd6a15eb3a80383a42e95128832742586b1afcc134925e28f26baa87b697c8396ec480f5961e3229d68968d0a87938248cceb8c74fc308668e1251bd64092efdf88aff0591b07d925501808488f09cd4320ee4542a6aa4d448088d0ba7837ee3cf92ac4c57b7cba7855f85c496e9dab196fa8f18cb8dd465cbef746b9075d4e2ca56fb342893b6e5ff6951373d1a6e66e86d35a8c4706eda9e14c0827502dae27a6d7de49c20f0c78b5b4d6dc614a5c1391283598b9e54ecd18b8561ab970442bcb74d6f31476d593dcab7b0b75450244034ebc8ad6c4e2f949ed09522ca635c3305433c722eede0de9ac5b596b98dfa385d769598105ed70ea4971638bd86a165501bf0404e2953a18f2698f45df7c0c4558533f55cb721616c66fda051575d4f2b21f946e45a6bbda602b5fb21d0e8a19ec9db4887d9c5cc8b04605972d9e7e22a6f7d0f9bb95c4831e9e87aa879dbcc557f9c08ab4d42d2bc15756ef06315263"
	srpVectorK  = "bbcf165d960bab61d44e6cd0f71c7e320d1bc0ba4457d6479debf688edf2c606575f11b5d0a3b33c3d06221eb72faf24c9b6ba8f668b949412f4cfeb16548620"
	srpVectorM1 = "c231123e313be6ee75d300387c05b4077ab910cb6316e782287989193b809e221ede4766442f0a49f87fa8fc5039f662eb6961120ccb726abc21e1e56f03a08e"
	srpVectorM2 = "b2b446d3ed3b9f19187fb93b02962eef9bc113588bfb44276e49d41cded6185c97f23d1884cf8285ef88518e0d6f0911296b1ee8e89ec158dadc519ef1fed010"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSRPMatchesPyatvVectors(t *testing.T) {
	salt := unhex(t, "00112233445566778899aabbccddeeff")
	a := new(big.Int).SetBytes(bytes.Repeat([]byte{0xaa}, 32))
	b := new(big.Int).SetBytes(bytes.Repeat([]byte{0xbb}, 32))

	client := newSRPClient(SRPUsername, "1111", a)
	if got := hex.EncodeToString(client.Public()); got != srpVectorA {
		t.Fatalf("A = %s", got)
	}
	server := newSRPServer(SRPUsername, "1111", salt, b)
	if got := hex.EncodeToString(server.Public()); got != srpVectorB {
		t.Fatalf("B = %s", got)
	}
	if err := client.SetServer(salt, server.Public()); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(client.SessionKey()); got != srpVectorK {
		t.Fatalf("K = %s", got)
	}
	if got := hex.EncodeToString(client.Proof()); got != srpVectorM1 {
		t.Fatalf("M1 = %s", got)
	}
	if err := server.SetClient(client.Public(), client.Proof()); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(server.Proof()); got != srpVectorM2 {
		t.Fatalf("M2 = %s", got)
	}
	if !client.VerifyServerProof(server.Proof()) {
		t.Fatal("client rejected the server proof")
	}
	if !bytes.Equal(client.SessionKey(), server.SessionKey()) {
		t.Fatal("session keys differ")
	}
}

func TestSRPWrongPIN(t *testing.T) {
	salt := unhex(t, "00112233445566778899aabbccddeeff")
	server, err := NewSRPServer(SRPUsername, "1111", salt)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewSRPClient(SRPUsername, "2222")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SetServer(salt, server.Public()); err != nil {
		t.Fatal(err)
	}
	err = server.SetClient(client.Public(), client.Proof())
	if err == nil || !strings.Contains(err.Error(), "proof is wrong") {
		t.Fatalf("got %v", err)
	}
	if client.VerifyServerProof(make([]byte, 64)) {
		t.Fatal("accepted a zero proof")
	}
}

func TestSRPRejectsZeroPublicValue(t *testing.T) {
	client, _ := NewSRPClient(SRPUsername, "1111")
	if err := client.SetServer([]byte{1}, srpBytes(srpN)); err == nil {
		t.Fatal("B = N accepted")
	}
	server, _ := NewSRPServer(SRPUsername, "1111", []byte{1})
	if err := server.SetClient([]byte{0}, nil); err == nil {
		t.Fatal("A = 0 accepted")
	}
}
