# Working in go-atv

A Go port of the Companion-protocol and pairing code of pyatv. It controls an
Apple TV: pairing, remote keys, touchpad, power, media, apps, discovery.

- **Plain names, standard library.** The only dependencies are
  `golang.org/x/crypto` for ChaCha20-Poly1305 and `grandcat/zeroconf` for
  discovery, which is isolated in its own package so the core needs neither
  it nor any network to be tested.
- **Three layers, one direction.** `opack` is the serialization format,
  `hap` is HomeKit pairing, `companion` is the protocol on top. `companion`
  imports `hap` and `opack`; nothing imports `companion`.
- **Tests first, against a fake.** `companion/companiontest` is an in-process
  Apple TV. A behaviour exists when its test passes. Keep the fake honest:
  when the real device does something the client must handle, the fake does
  it too (the transaction ID on events is the standing example).
- **The reference is pyatv.** Byte-level choices follow it so credentials and
  the wire format are interchangeable. A change to them must still interop
  with pyatv's own fake device.
- **Comments say what a thing is.** Every exported name has a doc comment.

## Verify before you say it is done

```sh
make check    # gofmt, go vet, go test -race ./...
```
