package companion

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/traego/go-atv/hap"
	"github.com/traego/go-atv/opack"
)

// Pairing is a pair-setup in progress. StartPairing makes the device show
// its PIN; Finish takes the PIN and returns the credentials.
type Pairing struct {
	s     *session
	setup *hap.PairSetup
	name  string
	m2    []byte
}

// StartPairing connects to the device at addr, a host:port, and begins
// pair-setup. The device shows a four-digit PIN. name is how the device
// will list this pairing.
func StartPairing(ctx context.Context, addr, name string) (*Pairing, error) {
	nc, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	setup, err := hap.NewPairSetup()
	if err != nil {
		nc.Close()
		return nil, err
	}
	p := &Pairing{s: newSession(nc, nil), setup: setup, name: name}
	resp, err := p.s.handshake(ctx, FramePSStart, map[string]any{"_pd": setup.M1(), "_pwTy": 1})
	if err != nil {
		p.Close()
		return nil, err
	}
	if p.m2, err = pairingData(resp); err != nil {
		p.Close()
		return nil, err
	}
	return p, nil
}

// Finish proves the PIN the device shows, including any leading zeros, and
// returns the credentials. The device's description of itself from the last
// message, with its name and model, comes back as well. Finish closes the
// connection either way; a wrong PIN needs a new StartPairing.
func (p *Pairing) Finish(ctx context.Context, pin string) (hap.Credentials, map[string]any, error) {
	defer p.Close()
	m3, err := p.setup.M3(p.m2, pin)
	if err != nil {
		return hap.Credentials{}, nil, err
	}
	resp, err := p.s.handshake(ctx, FramePSNext, map[string]any{"_pd": m3, "_pwTy": 1})
	if err != nil {
		return hap.Credentials{}, nil, err
	}
	m4, err := pairingData(resp)
	if err != nil {
		return hap.Credentials{}, nil, err
	}
	nameData, err := opack.Encode(map[string]any{"name": p.name})
	if err != nil {
		return hap.Credentials{}, nil, err
	}
	m5, err := p.setup.M5(m4, hap.Item{Type: hap.TLVName, Value: nameData})
	if err != nil {
		return hap.Credentials{}, nil, err
	}
	resp, err = p.s.handshake(ctx, FramePSNext, map[string]any{"_pd": m5, "_pwTy": 1})
	if err != nil {
		return hap.Credentials{}, nil, err
	}
	m6, err := pairingData(resp)
	if err != nil {
		return hap.Credentials{}, nil, err
	}
	creds, extra, err := p.setup.Finish(m6)
	if err != nil {
		return hap.Credentials{}, nil, err
	}
	var info map[string]any
	if packed, ok := extra[hap.TLVName]; ok {
		if v, _, err := opack.Decode(packed); err == nil {
			info, _ = v.(map[string]any)
		}
	}
	return creds, info, nil
}

// Close ends the pairing without finishing it.
func (p *Pairing) Close() error { return p.s.close() }

// Pair is StartPairing and Finish in one call. pin is called once the
// device shows the PIN.
func Pair(ctx context.Context, addr, name string, pin func(ctx context.Context) (string, error)) (hap.Credentials, map[string]any, error) {
	p, err := StartPairing(ctx, addr, name)
	if err != nil {
		return hap.Credentials{}, nil, err
	}
	code, err := pin(ctx)
	if err != nil {
		p.Close()
		return hap.Credentials{}, nil, err
	}
	return p.Finish(ctx, code)
}

// pairingData takes the TLV8 out of a pairing frame's _pd field.
func pairingData(resp map[string]any) ([]byte, error) {
	switch pd := resp["_pd"].(type) {
	case []byte:
		if len(pd) > 0 {
			return pd, nil
		}
	case nil:
	default:
		return nil, fmt.Errorf("companion: pairing data has type %T", pd)
	}
	return nil, errors.New("companion: no pairing data in device message")
}
