// Package hap implements the pairing half of Apple's HomeKit Accessory
// Protocol the way Apple's own device protocols use it. Companion, AirPlay 2
// and the media remote protocol all pair the same way: pair-setup proves a
// PIN with SRP and swaps long-term Ed25519 keys, pair-verify proves those
// keys on every later connection and agrees a session secret with X25519,
// and the session is then encrypted with ChaCha20-Poly1305.
//
// The package carries no transport. Each step takes the bytes the device
// sent and returns the bytes to send back; a protocol package wraps them in
// its own framing. The byte-level choices follow pyatv, which is the
// reference this port was made from, so credentials are interchangeable
// with it.
package hap
