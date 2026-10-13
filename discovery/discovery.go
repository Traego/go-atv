// Package discovery finds Companion devices on the local network. Apple TVs
// and HomePods advertise the service _companion-link._tcp over mDNS; Browse
// returns the ones it sees with the address and port to connect to.
//
// It is a thin convenience over a Bonjour browser and is the one part of
// this module that reaches the network to look around rather than to talk to
// a known device. A caller that already knows the address does not need it.
package discovery

import (
	"context"
	"net"
	"strconv"

	"github.com/grandcat/zeroconf"
)

// Service is the DNS-SD service type Companion devices advertise.
const Service = "_companion-link._tcp"

// Device is a Companion device found on the network.
type Device struct {
	// Name is the instance name, usually the device's name.
	Name string
	// Addr is the host:port to pass to companion.Dial or StartPairing. It
	// prefers an IPv4 address.
	Addr string
	// Port is the Companion port.
	Port int
	// Model is the device's model from the rpMd TXT field, such as
	// AppleTV6,2, when present.
	Model string
	// Fields is the raw TXT record, key to value.
	Fields map[string]string
}

// Browse looks for Companion devices until ctx is done and returns those it
// found. ctx should carry a timeout; without one Browse runs until canceled.
func Browse(ctx context.Context) ([]Device, error) {
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		return nil, err
	}
	entries := make(chan *zeroconf.ServiceEntry)
	if err := resolver.Browse(ctx, Service, "local.", entries); err != nil {
		return nil, err
	}
	var devices []Device
	for entry := range entries {
		devices = append(devices, deviceFromEntry(entry))
	}
	return devices, nil
}

func deviceFromEntry(entry *zeroconf.ServiceEntry) Device {
	d := Device{
		Name:   entry.Instance,
		Port:   entry.Port,
		Fields: map[string]string{},
	}
	for _, txt := range entry.Text {
		k, v, _ := cut(txt, '=')
		d.Fields[k] = v
		if k == "rpMd" {
			d.Model = v
		}
	}
	host := ""
	if len(entry.AddrIPv4) > 0 {
		host = entry.AddrIPv4[0].String()
	} else if len(entry.AddrIPv6) > 0 {
		host = entry.AddrIPv6[0].String()
	}
	if host != "" {
		d.Addr = net.JoinHostPort(host, strconv.Itoa(entry.Port))
	}
	return d
}

func cut(s string, sep byte) (before, after string, found bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}
