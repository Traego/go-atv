// Package companiontest is a fake Apple TV speaking the Companion protocol,
// for tests. It pairs with the PIN 1111, verifies pairings it made, and
// answers the requests the client sends the way pyatv's fake device does,
// recording what it was told.
package companiontest

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/traego/go-atv/companion"
	"github.com/traego/go-atv/hap"
	"github.com/traego/go-atv/opack"
)

// PIN is the PIN the server accepts.
const PIN = "1111"

// DeviceID is the identifier the server pairs under.
const DeviceID = "5D797FD3-3538-427E-A47B-A32FC6CF3A6A"

// Server is one fake device. Its exported fields may be set before clients
// connect; its state afterwards is read with State.
type Server struct {
	// Apps is what FetchLaunchableApplicationsEvent answers, bundle ID to
	// name.
	Apps map[string]string
	// Accounts is what FetchUserAccountsEvent answers, ID to name.
	Accounts map[string]string
	// StatusSupported says whether FetchAttentionState is answered. Newer
	// tvOS versions do not.
	StatusSupported bool
	// Drop names requests the server never answers, to test timeouts.
	Drop map[string]bool

	ln  net.Listener
	key ed25519.PrivateKey

	mu       sync.Mutex
	pairings map[string][]byte
	conns    map[*conn]bool
	state    State
}

// State is what the server has been told and what it did.
type State struct {
	// Presses are the buttons pressed and released, in order, by name.
	Presses []string
	// PoweredOn follows the sleep and wake buttons.
	PoweredOn bool
	// Status is the system status the server reports.
	Status companion.SystemStatus
	// SystemInfo is the last system information message.
	SystemInfo map[string]any
	// SessionID is the client's session ID, or 0 after the session stops.
	SessionID int64
	// TVRCProtocolVersion is what TVRCSessionStart carried.
	TVRCProtocolVersion string
	// Interests are the events subscribed to.
	Interests map[string]bool
	// ActiveApp is the last bundle ID launched; OpenURL the last URL.
	ActiveApp, OpenURL string
	// ActiveAccount is the last account switched to.
	ActiveAccount string
	// Volume is in percent.
	Volume float64
	// Position follows SkipBy, in seconds.
	Position float64
	// MediaCommands are the playback commands received, by name.
	MediaCommands []string
	// Touches are the touch events received.
	Touches []Touch
	// Pairings is how many clients have paired.
	Pairings int
}

// Touch is one touchpad event.
type Touch struct {
	Action companion.TouchAction
	X, Y   int64
}

// New starts a server on a loopback port.
func New() (*Server, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &Server{
		Apps:            map[string]string{},
		Accounts:        map[string]string{},
		StatusSupported: true,
		Drop:            map[string]bool{},
		ln:              ln,
		key:             key,
		pairings:        map[string][]byte{},
		conns:           map[*conn]bool{},
		state: State{
			PoweredOn: true,
			Status:    companion.StatusAwake,
			Interests: map[string]bool{},
			Volume:    10,
			Position:  10,
		},
	}
	go s.accept()
	return s, nil
}

// Addr is the host:port to connect to.
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Close stops the server and drops every connection.
func (s *Server) Close() error {
	err := s.ln.Close()
	s.mu.Lock()
	for c := range s.conns {
		c.nc.Close()
	}
	s.mu.Unlock()
	return err
}

// State returns a copy of the state.
func (s *Server) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.state
	st.Presses = append([]string(nil), st.Presses...)
	st.MediaCommands = append([]string(nil), st.MediaCommands...)
	st.Touches = append([]Touch(nil), st.Touches...)
	st.Interests = map[string]bool{}
	for k, v := range s.state.Interests {
		st.Interests[k] = v
	}
	return st
}

// AddPairing registers credentials the server should accept, so a test can
// skip pairing.
func (s *Server) AddPairing(creds hap.Credentials) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pairings[string(creds.ClientID)] = ed25519.NewKeyFromSeed(creds.LTSK).Public().(ed25519.PublicKey)
}

// Credentials makes credentials the server accepts, for a test that does not
// pair.
func (s *Server) Credentials() (hap.Credentials, error) {
	_, seed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return hap.Credentials{}, err
	}
	creds := hap.Credentials{
		LTPK:     s.key.Public().(ed25519.PublicKey),
		LTSK:     seed.Seed(),
		DeviceID: []byte(DeviceID),
		ClientID: []byte("4D797FD3-3538-427E-A47B-A32FC6CF3A6A"),
	}
	s.AddPairing(creds)
	return creds, nil
}

// SetStatus changes the system status and tells every connected client with
// a SystemStatus event, as the fake in pyatv does.
func (s *Server) SetStatus(st companion.SystemStatus) {
	s.mu.Lock()
	s.state.Status = st
	conns := make([]*conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		c.sendEvent(companion.EventSystemStatus, map[string]any{"state": int64(st)})
	}
}

func (s *Server) accept() {
	for {
		nc, err := s.ln.Accept()
		if err != nil {
			return
		}
		c := &conn{s: s, nc: nc, r: bufio.NewReader(nc)}
		s.mu.Lock()
		s.conns[c] = true
		s.mu.Unlock()
		go c.serve()
	}
}

func (s *Server) lookup(clientID []byte) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.pairings[string(clientID)]
	return k, ok
}

// conn is one client connection.
type conn struct {
	s      *Server
	nc     net.Conn
	r      *bufio.Reader
	wmu    sync.Mutex
	cipher *hap.SessionCipher
	setup  *hap.PairSetupDevice
	verify *hap.PairVerifyDevice
	keys   [2][]byte
	down   map[companion.Button]bool
}

func (c *conn) serve() {
	defer func() {
		c.nc.Close()
		c.s.mu.Lock()
		delete(c.s.conns, c)
		c.s.mu.Unlock()
	}()
	c.down = map[companion.Button]bool{}
	for {
		f, err := companion.ReadFrame(c.r, c.cipher)
		if err != nil {
			return
		}
		v, _, err := opack.Decode(f.Payload)
		if err != nil {
			return
		}
		msg, ok := v.(map[string]any)
		if !ok {
			return
		}
		switch f.Type {
		case companion.FramePSStart, companion.FramePSNext, companion.FramePVStart, companion.FramePVNext:
			if err := c.auth(f.Type, msg); err != nil {
				return
			}
		default:
			if c.cipher == nil {
				return
			}
			c.handle(msg)
		}
	}
}

func (c *conn) send(t companion.FrameType, msg map[string]any) {
	payload, err := opack.Encode(msg)
	if err != nil {
		panic(err)
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_ = companion.WriteFrame(c.nc, companion.Frame{Type: t, Payload: payload}, c.cipher)
}

func (c *conn) sendEvent(name string, content map[string]any) {
	c.send(companion.FrameEOpack, map[string]any{"_i": name, "_x": 1234, "_t": 1, "_c": content})
}

func (c *conn) respond(req map[string]any, content map[string]any) {
	c.send(companion.FrameEOpack, map[string]any{"_i": req["_i"], "_x": req["_x"], "_t": 3, "_c": content})
}

func (c *conn) fail(req map[string]any, message string, code int64) {
	c.send(companion.FrameEOpack, map[string]any{
		"_i": req["_i"], "_x": req["_x"], "_t": 3,
		"_ec": code, "_ed": "RPErrorDomain", "_em": message,
	})
}

// auth runs the device side of pair-setup and pair-verify.
func (c *conn) auth(t companion.FrameType, msg map[string]any) error {
	pd, _ := msg["_pd"].([]byte)
	tlv, err := hap.DecodeTLV8(pd)
	if err != nil {
		return err
	}
	state := tlv[hap.TLVState]
	if len(state) == 0 {
		return errors.New("no state")
	}
	var reply []byte
	switch {
	case t == companion.FramePSStart || t == companion.FramePSNext:
		switch state[0] {
		case 1:
			c.setup, err = hap.NewPairSetupDevice(PIN, []byte(DeviceID), c.s.key)
			if err != nil {
				return err
			}
			reply, err = c.setup.M2(pd)
			if err == nil {
				c.send(companion.FramePSNext, map[string]any{"_pd": reply, "_pwTy": 1})
				return nil
			}
		case 3:
			reply, err = c.setup.M4(pd)
		case 5:
			var pairing hap.Pairing
			info, _ := opack.Encode(map[string]any{
				"accountID": "DC6A7CB6-CA1A-4BF4-880D-A61B717814DB",
				"model":     "AppleTV6,2",
				"name":      "Living Room",
			})
			reply, pairing, err = c.setup.M6(pd, hap.Item{Type: hap.TLVName, Value: info})
			if err == nil {
				c.s.mu.Lock()
				c.s.pairings[string(pairing.ClientID)] = pairing.LTPK
				c.s.state.Pairings++
				c.s.mu.Unlock()
			}
		default:
			return fmt.Errorf("unexpected pair-setup state %d", state[0])
		}
		if reply != nil {
			c.send(companion.FramePSNext, map[string]any{"_pd": reply})
		}
		return err
	default:
		switch state[0] {
		case 1:
			c.verify = hap.NewPairVerifyDevice([]byte(DeviceID), c.s.key, c.s.lookup)
			reply, err = c.verify.M2(pd)
			if err == nil {
				c.keys[0], c.keys[1] = c.verify.SessionKeys("", "ClientEncrypt-main", "ServerEncrypt-main")
			}
		case 3:
			reply, err = c.verify.M4(pd)
			if err == nil {
				defer func() {
					c.cipher, _ = hap.NewSessionCipher(c.keys[0], c.keys[1])
				}()
			}
		default:
			return fmt.Errorf("unexpected pair-verify state %d", state[0])
		}
		if reply != nil {
			c.send(companion.FramePVNext, map[string]any{"_pd": reply})
		}
		return err
	}
}

func (c *conn) handle(msg map[string]any) {
	id, _ := msg["_i"].(string)
	content, _ := msg["_c"].(map[string]any)
	if content == nil {
		content = map[string]any{}
	}
	t, _ := msg["_t"].(int64)
	s := c.s
	if s.Drop[id] {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch id {
	case "_systemInfo":
		s.state.SystemInfo = content
		c.respond(msg, map[string]any{})
	case "_sessionStart":
		s.state.SessionID, _ = content["_sid"].(int64)
		c.respond(msg, map[string]any{"_sid": 5555})
	case "_sessionStop":
		if sid, _ := content["_sid"].(int64); sid == 5555<<32|s.state.SessionID {
			s.state.SessionID = 0
			c.respond(msg, map[string]any{})
		} else {
			c.fail(msg, "Invalid SID", 1337)
		}
	case "TVRCSessionStart":
		s.state.TVRCProtocolVersion, _ = content["ProtocolVersionKey"].(string)
		c.respond(msg, content)
	case "_touchStart":
		w, _ := content["_width"].(float64)
		h, _ := content["_height"].(float64)
		if w <= 0 || w > 1000 || h <= 0 || h > 1000 {
			c.fail(msg, "Invalid touchpad width or height", 1337)
		} else {
			c.respond(msg, map[string]any{})
		}
	case "_touchStop":
		c.respond(msg, map[string]any{})
	case "_interest":
		if reg, ok := content["_regEvents"].([]any); ok {
			xid, hasXID := msg["_x"].(int64)
			for _, e := range reg {
				name, _ := e.(string)
				s.state.Interests[name] = true
				if name == companion.EventMediaControls {
					// Echo the event's transaction ID, as a real device does;
					// a client that omits _x fails here.
					if !hasXID {
						continue
					}
					c.send(companion.FrameEOpack, map[string]any{
						"_i": companion.EventMediaControls, "_x": xid, "_t": int64(1),
						"_c": map[string]any{"_mcF": int64(companion.MediaControlVolume)},
					})
				}
			}
		}
		if dereg, ok := content["_deregEvents"].([]any); ok {
			for _, e := range dereg {
				name, _ := e.(string)
				delete(s.state.Interests, name)
			}
		}
	case "_hidC":
		c.hid(msg, content)
	case "_hidT":
		if t != 1 {
			return
		}
		action, _ := content["_tPh"].(int64)
		x, _ := content["_cx"].(int64)
		y, _ := content["_cy"].(int64)
		s.state.Touches = append(s.state.Touches, Touch{Action: companion.TouchAction(action), X: x, Y: y})
	case "_mcc":
		c.media(msg, content)
	case "_launchApp":
		if b, ok := content["_bundleID"].(string); ok {
			s.state.ActiveApp = b
		} else if u, ok := content["_urlS"].(string); ok {
			s.state.OpenURL = u
		}
		c.respond(msg, map[string]any{})
	case "FetchLaunchableApplicationsEvent":
		c.respond(msg, stringMap(s.Apps))
	case "FetchUserAccountsEvent":
		c.respond(msg, stringMap(s.Accounts))
	case "SwitchUserAccountEvent":
		s.state.ActiveAccount, _ = content["SwitchAccountID"].(string)
		c.respond(msg, map[string]any{})
	case "FetchAttentionState":
		if s.StatusSupported {
			c.respond(msg, map[string]any{"state": int64(s.state.Status)})
		} else {
			c.fail(msg, "No request handler", companion.ErrorNoHandler)
		}
	default:
		c.fail(msg, "No request handler", companion.ErrorNoHandler)
	}
}

// hid follows pyatv's fake: a release without a press is an error, sleep
// and wake act on release, and the rest are recorded on release.
func (c *conn) hid(msg, content map[string]any) {
	state, _ := content["_hBtS"].(int64)
	b := companion.Button(content["_hidC"].(int64))
	s := c.s
	switch {
	case state == 1:
		c.down[b] = true
	case b == companion.ButtonSleep:
		s.state.PoweredOn = false
	case b == companion.ButtonWake:
		s.state.PoweredOn = true
	default:
		if !c.down[b] {
			c.fail(msg, fmt.Sprintf("Missing button DOWN for %s", b), 1337)
			return
		}
		delete(c.down, b)
		s.state.Presses = append(s.state.Presses, b.String())
		switch b {
		case companion.ButtonVolumeUp:
			c.volume(s.state.Volume + 5)
		case companion.ButtonVolumeDown:
			c.volume(s.state.Volume - 5)
		}
	}
	c.respond(msg, map[string]any{})
}

func (c *conn) volume(v float64) {
	c.s.state.Volume = min(max(v, 0), 100)
	go c.sendEvent(companion.EventMediaControls, map[string]any{"_mcF": int64(companion.MediaControlVolume)})
}

func (c *conn) media(msg, content map[string]any) {
	s := c.s
	cmd := companion.MediaControlCommand(content["_mcc"].(int64))
	out := map[string]any{}
	switch cmd {
	case companion.MediaSetVolume:
		v, _ := content["_vol"].(float64)
		c.volume(v * 100)
	case companion.MediaGetVolume:
		out["_vol"] = s.state.Volume / 100
	case companion.MediaSkipBy:
		by, _ := content["_skpS"].(float64)
		s.state.Position = max(0, s.state.Position+by)
	case companion.MediaPlay, companion.MediaPause, companion.MediaNextTrack, companion.MediaPreviousTrack:
		names := map[companion.MediaControlCommand]string{
			companion.MediaPlay: "play", companion.MediaPause: "pause",
			companion.MediaNextTrack: "next", companion.MediaPreviousTrack: "previous",
		}
		s.state.MediaCommands = append(s.state.MediaCommands, names[cmd])
	default:
		c.fail(msg, "Unsupported media control command", 1337)
		return
	}
	c.respond(msg, out)
}

func stringMap(m map[string]string) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = v
	}
	return out
}
