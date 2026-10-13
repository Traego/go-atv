// Package companion speaks the Companion Link protocol, the one the Apple
// TV Remote on an iPhone uses to control an Apple TV: wake and sleep, the
// remote's buttons, touchpad gestures, media playback, launching apps, and
// a few more.
//
// Pairing happens once, with a PIN the Apple TV shows on screen, and gives
// Credentials that every later connection presents. See StartPairing and
// Dial.
//
// On the wire a connection carries frames: one type byte, a three-byte
// length and a payload. The payload of most frames is an OPACK dictionary,
// and after pair-verify it is sealed with ChaCha20-Poly1305. This package is
// a port of pyatv's Companion support; the protocol is Apple's and is not
// documented by them.
package companion
