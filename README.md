# go-atv

A Go library for controlling an Apple TV over the **Companion Link**
protocol, the one the Apple TV Remote on an iPhone uses. It is a focused port
of the Companion and pairing code of [pyatv](https://github.com/postlund/pyatv).

What it does:

- **Pair** with an Apple TV using the PIN it shows on screen, and store the
  resulting credentials.
- **Remote control**: the arrows, select, menu, home, play/pause, the volume
  keys, channel up and down, and the rest.
- **Touchpad**: taps and swipes.
- **Power**: wake and sleep (the Apple TV has no hard power-off; "off" is
  sleep, and with HDMI-CEC the attached TV follows).
- **Media**: play, pause, next, previous, skip, and volume.
- **Apps and accounts**: list and launch apps, list and switch user accounts.
- **Status**: read and subscribe to the device's awake/asleep state.
- **Discover** devices on the network with mDNS.

It does **not** do AirPlay, the media remote protocol (MRP), or now-playing
metadata. Companion alone covers remote control and power.

## Install

```sh
go get github.com/traego/go-atv
```

## Library

```go
// Pair once. The Apple TV shows a PIN.
creds, _, err := companion.Pair(ctx, "10.0.0.5:49152", "My App",
    func(ctx context.Context) (string, error) {
        return askTheUserForThePIN(ctx)
    })
// Keep creds.String(); every later connection needs it.

// Connect and control.
c, err := companion.Dial(ctx, "10.0.0.5:49152", creds, companion.Identity{})
defer c.Close()

c.Press(ctx, companion.ButtonSelect)
c.Press(ctx, companion.ButtonUp)
c.TurnOff(ctx)
c.LaunchApp(ctx, "com.netflix.Netflix")
```

The three lower packages are usable on their own:

- `opack` encodes and decodes Apple's OPACK serialization format.
- `hap` is the HomeKit pairing (pair-setup and pair-verify, SRP, the session
  cipher). The same pairing underlies AirPlay 2 and MRP, so it is kept apart
  from Companion.
- `companion` is the protocol: framing, the client, pairing, and the command
  set.

## Command line

```sh
atv discover
atv pair 10.0.0.5:49152 "My Mac"       # prints credentials
export ATV_CREDENTIALS=....
atv 10.0.0.5:49152 button up
atv 10.0.0.5:49152 tap
atv 10.0.0.5:49152 off
atv 10.0.0.5:49152 launch com.netflix.Netflix
```

## Tests

```sh
make check
```

The tests use an in-process fake Apple TV and need no hardware or network.
OPACK is checked against Apple's own encoder, SRP against fixed vectors from
the library pyatv uses, and the whole stack against pyatv's reference fake
device.

## How it works

A Companion connection carries framed messages: a type byte, a three-byte
length, and a payload. Pairing is HomeKit's: pair-setup proves the PIN with
SRP and exchanges long-term Ed25519 keys; pair-verify proves those keys on
each connection and agrees a session secret; the session is then encrypted
with ChaCha20-Poly1305. Message payloads are OPACK dictionaries. The protocol
is Apple's and is not publicly documented; what is here was reverse
engineered by the pyatv project and checked against Apple's own tools.

## Credit

This is a port of [pyatv](https://github.com/postlund/pyatv) by Pierre Ståhl,
used under the MIT License. See `LICENSE`.
