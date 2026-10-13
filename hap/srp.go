package hap

import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"math/big"
	"strings"
)

// The SRP-6a group every Apple pairing uses: the 3072-bit prime of RFC 5054,
// generator 5, and SHA-512. The byte-level conventions follow pyatv's SRP
// library, srptools: values are minimal big-endian, except where the
// specification pads to the prime's width.
var (
	srpN     = mustInt(srpPrimeHex)
	srpG     = big.NewInt(5)
	srpNSize = len(srpN.Bytes())
	// srpK is the multiplier k = H(N | PAD(g)).
	srpK = srpInt(srpHash(srpBytes(srpN), srpPad(srpG)))
)

// SRPUsername is the user name every pairing uses.
const SRPUsername = "Pair-Setup"

func mustInt(hexDigits string) *big.Int {
	n, ok := new(big.Int).SetString(strings.ReplaceAll(hexDigits, "\n", ""), 16)
	if !ok {
		panic("hap: bad SRP prime")
	}
	return n
}

func srpHash(parts ...[]byte) []byte {
	h := sha512.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func srpInt(b []byte) *big.Int { return new(big.Int).SetBytes(b) }

// srpBytes is the minimal big-endian encoding, one byte for zero.
func srpBytes(x *big.Int) []byte {
	b := x.Bytes()
	if len(b) == 0 {
		return []byte{0}
	}
	return b
}

// srpPad is the big-endian encoding padded to the prime's width.
func srpPad(x *big.Int) []byte {
	return x.FillBytes(make([]byte, srpNSize))
}

// srpPasswordHash is x = H(s | H(I ":" P)).
func srpPasswordHash(salt []byte, username, password string) *big.Int {
	return srpInt(srpHash(salt, srpHash([]byte(username+":"+password))))
}

// srpSharedHash is u = H(PAD(A) | PAD(B)).
func srpSharedHash(a, b *big.Int) *big.Int {
	return srpInt(srpHash(srpPad(a), srpPad(b)))
}

// srpClientProof is M1 = H(H(N) xor H(g) | H(I) | s | A | B | K).
func srpClientProof(username string, salt []byte, a, b *big.Int, key []byte) []byte {
	hn := srpInt(srpHash(srpBytes(srpN)))
	hg := srpInt(srpHash(srpBytes(srpG)))
	hu := srpInt(srpHash([]byte(username)))
	return srpHash(srpBytes(new(big.Int).Xor(hn, hg)), srpBytes(hu), salt, srpBytes(a), srpBytes(b), key)
}

// srpServerProof is M2 = H(A | M1 | K).
func srpServerProof(a *big.Int, clientProof, key []byte) []byte {
	return srpHash(srpBytes(a), clientProof, key)
}

func srpRandom() (*big.Int, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return srpInt(b), nil
}

// SRPClient is the side that knows the PIN and proves it.
type SRPClient struct {
	username, password string
	a, pub             *big.Int
	key, proof, expect []byte
}

// NewSRPClient starts a client for username and password. The password is
// the PIN as the device shows it.
func NewSRPClient(username, password string) (*SRPClient, error) {
	a, err := srpRandom()
	if err != nil {
		return nil, err
	}
	return newSRPClient(username, password, a), nil
}

func newSRPClient(username, password string, a *big.Int) *SRPClient {
	return &SRPClient{
		username: username,
		password: password,
		a:        a,
		pub:      new(big.Int).Exp(srpG, a, srpN),
	}
}

// Public is A, our public value.
func (c *SRPClient) Public() []byte { return srpBytes(c.pub) }

// SetServer takes the device's salt and public value B, and computes the
// session key and both proofs.
func (c *SRPClient) SetServer(salt, serverPublic []byte) error {
	b := srpInt(serverPublic)
	if new(big.Int).Mod(b, srpN).Sign() == 0 {
		return errors.New("hap: device sent an invalid SRP public value")
	}
	u := srpSharedHash(c.pub, b)
	x := srpPasswordHash(salt, c.username, c.password)
	v := new(big.Int).Exp(srpG, x, srpN)
	// S = (B - k*v) ^ (a + u*x) mod N
	base := new(big.Int).Mul(srpK, v)
	base.Sub(b, base)
	base.Mod(base, srpN)
	exp := new(big.Int).Mul(u, x)
	exp.Add(exp, c.a)
	s := new(big.Int).Exp(base, exp, srpN)
	c.key = srpHash(srpBytes(s))
	c.proof = srpClientProof(c.username, salt, c.pub, b, c.key)
	c.expect = srpServerProof(c.pub, c.proof, c.key)
	return nil
}

// Proof is M1, our proof of the password. SetServer must have run.
func (c *SRPClient) Proof() []byte { return c.proof }

// VerifyServerProof checks M2, the device's proof that it knew the password
// too. SetServer must have run.
func (c *SRPClient) VerifyServerProof(proof []byte) bool {
	return c.expect != nil && subtle.ConstantTimeCompare(proof, c.expect) == 1
}

// SessionKey is K, the shared secret the pairing keys derive from. SetServer
// must have run.
func (c *SRPClient) SessionKey() []byte { return c.key }

// SRPServer is the device side: it knows the password's verifier and checks
// the client's proof. The companion test server uses it; a real Apple TV is
// always the server.
type SRPServer struct {
	username   string
	salt       []byte
	verifier   *big.Int
	b, pub     *big.Int
	key, proof []byte
}

// NewSRPServer starts a server for username and password with the given
// salt.
func NewSRPServer(username, password string, salt []byte) (*SRPServer, error) {
	b, err := srpRandom()
	if err != nil {
		return nil, err
	}
	return newSRPServer(username, password, salt, b), nil
}

func newSRPServer(username, password string, salt []byte, b *big.Int) *SRPServer {
	x := srpPasswordHash(salt, username, password)
	v := new(big.Int).Exp(srpG, x, srpN)
	// B = (k*v + g^b) mod N
	pub := new(big.Int).Mul(srpK, v)
	pub.Add(pub, new(big.Int).Exp(srpG, b, srpN))
	pub.Mod(pub, srpN)
	return &SRPServer{username: username, salt: salt, verifier: v, b: b, pub: pub}
}

// Salt is the salt the client needs.
func (s *SRPServer) Salt() []byte { return s.salt }

// Public is B, the server's public value.
func (s *SRPServer) Public() []byte { return srpBytes(s.pub) }

// SetClient takes the client's public value A and proof M1. It fails if the
// proof is wrong, which means the client had the wrong password.
func (s *SRPServer) SetClient(clientPublic, proof []byte) error {
	a := srpInt(clientPublic)
	if new(big.Int).Mod(a, srpN).Sign() == 0 {
		return errors.New("hap: client sent an invalid SRP public value")
	}
	u := srpSharedHash(a, s.pub)
	// S = (A * v^u) ^ b mod N
	base := new(big.Int).Exp(s.verifier, u, srpN)
	base.Mul(base, a)
	base.Mod(base, srpN)
	sec := new(big.Int).Exp(base, s.b, srpN)
	key := srpHash(srpBytes(sec))
	expect := srpClientProof(s.username, s.salt, a, s.pub, key)
	if subtle.ConstantTimeCompare(proof, expect) != 1 {
		return errors.New("hap: client proof is wrong")
	}
	s.key = key
	s.proof = srpServerProof(a, proof, key)
	return nil
}

// Proof is M2, the server's proof. SetClient must have succeeded.
func (s *SRPServer) Proof() []byte { return s.proof }

// SessionKey is K. SetClient must have succeeded.
func (s *SRPServer) SessionKey() []byte { return s.key }

// srpPrimeHex is the 3072-bit MODP prime of RFC 3526 and RFC 5054.
const srpPrimeHex = `
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74
020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437
4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05
98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB
9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718
3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33
A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7
ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864
D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2
08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF
`
