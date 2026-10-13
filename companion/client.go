package companion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/traego/go-atv/hap"
)

// Identity is how we describe ourselves to the device in the system
// information message sent on connect. Fields left empty are filled in: a
// name of "go-atv", a model of "iPhone10,6", and identifiers derived from
// the credentials so they stay the same from one connection to the next,
// which the device needs before it will push status events.
type Identity struct {
	// Name is what the device shows for us.
	Name string
	// Model is the hardware we claim to be.
	Model string
	// DeviceID is a MAC-style public identifier.
	DeviceID string
	// ID is the identifier the device files status events under.
	ID string
}

func (id Identity) withDefaults(creds hap.Credentials) Identity {
	sum := sha256.Sum256(creds.ClientID)
	if id.Name == "" {
		id.Name = "go-atv"
	}
	if id.Model == "" {
		id.Model = "iPhone10,6"
	}
	if id.DeviceID == "" {
		b := sum[:6]
		id.DeviceID = fmt.Sprintf("02:%02X:%02X:%02X:%02X:%02X", b[1], b[2], b[3], b[4], b[5])
	}
	if id.ID == "" {
		id.ID = hex.EncodeToString(sum[6:12])
	}
	return id
}

// The touchpad the device is told about.
const (
	touchpadWidth  = 1000.0
	touchpadHeight = 1000.0
	touchpadDelay  = 16 * time.Millisecond
)

// Client is a connection to a paired device.
type Client struct {
	s        *session
	identity Identity
	sid      int64
	base     time.Time

	mu         sync.Mutex
	handlers   map[string][]func(map[string]any)
	subscribed []string
}

// Dial connects to the device at addr, a host:port, verifies the pairing,
// and sets the session up the way the Apple TV Remote does. identity may be
// the zero value.
func Dial(ctx context.Context, addr string, creds hap.Credentials, identity Identity) (*Client, error) {
	if err := creds.Valid(); err != nil {
		return nil, err
	}
	nc, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	c := &Client{identity: identity.withDefaults(creds), handlers: map[string][]func(map[string]any){}}
	c.s = newSession(nc, c.event)
	if err := c.verify(ctx, creds); err != nil {
		c.s.close()
		return nil, err
	}
	// The handshake is done and encryption is on; from here the read loop
	// handles responses and events.
	c.s.start()
	if err := c.setup(ctx, creds); err != nil {
		c.s.close()
		return nil, err
	}
	return c, nil
}

func (c *Client) verify(ctx context.Context, creds hap.Credentials) error {
	v, err := hap.NewPairVerify(creds)
	if err != nil {
		return err
	}
	resp, err := c.s.handshake(ctx, FramePVStart, map[string]any{"_pd": v.M1(), "_auTy": 4})
	if err != nil {
		return err
	}
	m2, err := pairingData(resp)
	if err != nil {
		return err
	}
	m3, err := v.M3(m2)
	if err != nil {
		return err
	}
	resp, err = c.s.handshake(ctx, FramePVNext, map[string]any{"_pd": m3})
	if err != nil {
		return err
	}
	m4, err := pairingData(resp)
	if err != nil {
		return err
	}
	if err := v.Finish(m4); err != nil {
		return err
	}
	output, input := v.SessionKeys("", "ClientEncrypt-main", "ServerEncrypt-main")
	return c.s.enableEncryption(output, input)
}

// setup is what the remote app sends after verifying: who we are, a
// touchpad, a session, and interest in the media controls.
func (c *Client) setup(ctx context.Context, creds hap.Credentials) error {
	_, err := c.Request(ctx, "_systemInfo", map[string]any{
		"_bf":    0,
		"_cf":    512,
		"_clFl":  128,
		"_i":     c.identity.ID,
		"_idsID": creds.ClientID,
		"_pubID": c.identity.DeviceID,
		"_sf":    256,
		"_sv":    "170.18",
		"model":  c.identity.Model,
		"name":   c.identity.Name,
	})
	if err != nil {
		return fmt.Errorf("system info: %w", err)
	}
	c.base = time.Now()
	if _, err := c.Request(ctx, "_touchStart", map[string]any{"_height": touchpadHeight, "_tFl": 0, "_width": touchpadWidth}); err != nil {
		return fmt.Errorf("touch start: %w", err)
	}
	local := rand.Int64N(1 << 32)
	resp, err := c.Request(ctx, "_sessionStart", map[string]any{"_srvT": "com.apple.tvremoteservices", "_sid": local})
	if err != nil {
		return fmt.Errorf("session start: %w", err)
	}
	remote, ok := resp["_sid"].(int64)
	if !ok {
		return errors.New("companion: session start answered without a session ID")
	}
	c.sid = remote<<32 | local
	// Newer tvOS versions want a TV remote client session before they
	// answer FetchAttentionState; older ones do not know the request.
	_, _ = c.Request(ctx, "TVRCSessionStart", map[string]any{"ProtocolVersionKey": "1.2"})
	return c.Subscribe(ctx, EventMediaControls)
}

// Close ends the session and closes the connection.
func (c *Client) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c.mu.Lock()
	subscribed := slices.Clone(c.subscribed)
	c.mu.Unlock()
	for _, e := range subscribed {
		_ = c.Unsubscribe(ctx, e)
	}
	_, _ = c.Request(ctx, "_sessionStop", map[string]any{"_srvT": "com.apple.tvremoteservices", "_sid": c.sid})
	_, _ = c.Request(ctx, "_touchStop", map[string]any{"_i": 1})
	return c.s.close()
}

// Done is closed when the connection ends, for any reason.
func (c *Client) Done() <-chan struct{} { return c.s.done }

// Err is why the connection ended, or nil while it is up.
func (c *Client) Err() error {
	c.s.mu.Lock()
	defer c.s.mu.Unlock()
	return c.s.err
}

// Request sends a request and returns the content of the response, the _c
// field, which may be nil. It is the escape hatch for anything this package
// has no method for.
func (c *Client) Request(ctx context.Context, id string, content map[string]any) (map[string]any, error) {
	if content == nil {
		content = map[string]any{}
	}
	resp, err := c.s.request(ctx, map[string]any{"_i": id, "_c": content})
	if err != nil {
		return nil, err
	}
	out, _ := resp["_c"].(map[string]any)
	return out, nil
}

// Event sends an event, which has no response.
func (c *Client) Event(id string, content map[string]any) error {
	if content == nil {
		content = map[string]any{}
	}
	return c.s.event(id, content)
}

// Handle registers fn for events named name. Handlers run on their own
// goroutines, so they may call the client.
func (c *Client) Handle(name string, fn func(content map[string]any)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.handlers[name] = append(c.handlers[name], fn)
}

func (c *Client) event(name string, content map[string]any) {
	c.mu.Lock()
	fns := slices.Clone(c.handlers[name])
	c.mu.Unlock()
	for _, fn := range fns {
		go fn(content)
	}
}

// Subscribe asks the device to send events named name.
func (c *Client) Subscribe(ctx context.Context, name string) error {
	c.mu.Lock()
	for _, e := range c.subscribed {
		if e == name {
			c.mu.Unlock()
			return nil
		}
	}
	c.subscribed = append(c.subscribed, name)
	c.mu.Unlock()
	return c.Event("_interest", map[string]any{"_regEvents": []any{name}})
}

// Unsubscribe stops events named name.
func (c *Client) Unsubscribe(ctx context.Context, name string) error {
	c.mu.Lock()
	kept := c.subscribed[:0]
	for _, e := range c.subscribed {
		if e != name {
			kept = append(kept, e)
		}
	}
	c.subscribed = kept
	c.mu.Unlock()
	return c.Event("_interest", map[string]any{"_deregEvents": []any{name}})
}

// Button sends one half of a button press: down or up.
func (c *Client) Button(ctx context.Context, b Button, down bool) error {
	state := int64(2)
	if down {
		state = 1
	}
	_, err := c.Request(ctx, "_hidC", map[string]any{"_hBtS": state, "_hidC": int64(b)})
	return err
}

// Press presses and releases a button.
func (c *Client) Press(ctx context.Context, b Button) error {
	if err := c.Button(ctx, b, true); err != nil {
		return err
	}
	return c.Button(ctx, b, false)
}

// Hold presses a button, waits, and releases it.
func (c *Client) Hold(ctx context.Context, b Button, d time.Duration) error {
	if err := c.Button(ctx, b, true); err != nil {
		return err
	}
	select {
	case <-time.After(d):
	case <-ctx.Done():
		_ = c.Button(context.Background(), b, false)
		return ctx.Err()
	}
	return c.Button(ctx, b, false)
}

// TurnOn wakes the device.
func (c *Client) TurnOn(ctx context.Context) error { return c.Button(ctx, ButtonWake, false) }

// TurnOff puts the device to sleep.
func (c *Client) TurnOff(ctx context.Context) error { return c.Button(ctx, ButtonSleep, false) }

// SystemStatus asks the device whether it is awake. Newer tvOS versions
// answer with a CommandError of ErrorNoHandler; subscribe to
// EventSystemStatus and EventTVSystemStatus to track it instead.
func (c *Client) SystemStatus(ctx context.Context) (SystemStatus, error) {
	content, err := c.Request(ctx, "FetchAttentionState", nil)
	if err != nil {
		return StatusUnknown, err
	}
	state, ok := content["state"].(int64)
	if !ok {
		return StatusUnknown, errors.New("companion: attention state missing from response")
	}
	return SystemStatus(state), nil
}

// StatusFromEvent reads the status out of an EventSystemStatus or
// EventTVSystemStatus event's content.
func StatusFromEvent(content map[string]any) (SystemStatus, bool) {
	state, ok := content["state"].(int64)
	return SystemStatus(state), ok
}

// LaunchApp opens an app by bundle identifier, such as com.apple.TVMusic,
// or a URL or URL scheme.
func (c *Client) LaunchApp(ctx context.Context, bundleIDOrURL string) error {
	key := "_bundleID"
	if hasScheme(bundleIDOrURL) {
		key = "_urlS"
	}
	_, err := c.Request(ctx, "_launchApp", map[string]any{key: bundleIDOrURL})
	return err
}

// hasScheme reports whether s starts with a URL scheme and a colon.
func hasScheme(s string) bool {
	for i, r := range s {
		switch {
		case r == ':':
			return i > 0
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case i > 0 && (r >= '0' && r <= '9' || r == '+' || r == '-' || r == '.'):
		default:
			return false
		}
	}
	return false
}

// App is an app the device can launch.
type App struct {
	Name     string
	BundleID string
}

// Apps lists the apps the device can launch.
func (c *Client) Apps(ctx context.Context) ([]App, error) {
	content, err := c.Request(ctx, "FetchLaunchableApplicationsEvent", nil)
	if err != nil {
		return nil, err
	}
	var apps []App
	for id, name := range content {
		n, _ := name.(string)
		apps = append(apps, App{Name: n, BundleID: id})
	}
	return apps, nil
}

// Account is a user account on the device.
type Account struct {
	Name string
	ID   string
}

// Accounts lists the user accounts the device can switch between.
func (c *Client) Accounts(ctx context.Context) ([]Account, error) {
	content, err := c.Request(ctx, "FetchUserAccountsEvent", nil)
	if err != nil {
		return nil, err
	}
	var accounts []Account
	for id, name := range content {
		n, _ := name.(string)
		accounts = append(accounts, Account{Name: n, ID: id})
	}
	return accounts, nil
}

// SwitchAccount makes the account with the given ID the active one.
func (c *Client) SwitchAccount(ctx context.Context, id string) error {
	_, err := c.Request(ctx, "SwitchUserAccountEvent", map[string]any{"SwitchAccountID": id})
	return err
}

// MediaControl sends a playback command with any arguments it takes and
// returns the response's content.
func (c *Client) MediaControl(ctx context.Context, cmd MediaControlCommand, args map[string]any) (map[string]any, error) {
	content := map[string]any{"_mcc": int64(cmd)}
	for k, v := range args {
		content[k] = v
	}
	return c.Request(ctx, "_mcc", content)
}

// Play starts playback.
func (c *Client) Play(ctx context.Context) error {
	_, err := c.MediaControl(ctx, MediaPlay, nil)
	return err
}

// Pause pauses playback.
func (c *Client) Pause(ctx context.Context) error {
	_, err := c.MediaControl(ctx, MediaPause, nil)
	return err
}

// NextTrack skips to the next track.
func (c *Client) NextTrack(ctx context.Context) error {
	_, err := c.MediaControl(ctx, MediaNextTrack, nil)
	return err
}

// PreviousTrack goes back a track.
func (c *Client) PreviousTrack(ctx context.Context) error {
	_, err := c.MediaControl(ctx, MediaPreviousTrack, nil)
	return err
}

// SkipBy moves playback by a number of seconds, negative to go back.
func (c *Client) SkipBy(ctx context.Context, seconds float64) error {
	_, err := c.MediaControl(ctx, MediaSkipBy, map[string]any{"_skpS": seconds})
	return err
}

// Volume returns the volume as a percentage.
func (c *Client) Volume(ctx context.Context) (float64, error) {
	content, err := c.MediaControl(ctx, MediaGetVolume, nil)
	if err != nil {
		return 0, err
	}
	v, ok := content["_vol"].(float64)
	if !ok {
		return 0, errors.New("companion: volume missing from response")
	}
	return v * 100, nil
}

// SetVolume sets the volume as a percentage.
func (c *Client) SetVolume(ctx context.Context, percent float64) error {
	_, err := c.MediaControl(ctx, MediaSetVolume, map[string]any{"_vol": percent / 100})
	return err
}

// Touch sends one touchpad event at x, y in a 1000 by 1000 space.
func (c *Client) Touch(ctx context.Context, x, y int, action TouchAction) error {
	return c.Event("_hidT", map[string]any{
		"_ns":  time.Since(c.base).Nanoseconds(),
		"_tFg": 1,
		"_cx":  min(max(x, 0), int(touchpadWidth)),
		"_tPh": int64(action),
		"_cy":  min(max(y, 0), int(touchpadHeight)),
	})
}

// Swipe drags from one point to another over the given time.
func (c *Client) Swipe(ctx context.Context, fromX, fromY, toX, toY int, d time.Duration) error {
	if err := c.Touch(ctx, fromX, fromY, TouchPress); err != nil {
		return err
	}
	end := time.Now().Add(d)
	x, y := float64(fromX), float64(fromY)
	for now := time.Now(); now.Before(end); now = time.Now() {
		left := float64(end.Sub(now))
		x += (float64(toX) - x) * float64(touchpadDelay) / left
		y += (float64(toY) - y) * float64(touchpadDelay) / left
		if err := c.Touch(ctx, int(x), int(y), TouchHold); err != nil {
			return err
		}
		select {
		case <-time.After(touchpadDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return c.Touch(ctx, toX, toY, TouchRelease)
}

// Tap clicks the touchpad: a select press followed by a click event, which
// is what a tap on the Siri Remote sends.
func (c *Client) Tap(ctx context.Context) error {
	if err := c.Button(ctx, ButtonSelect, true); err != nil {
		return err
	}
	time.Sleep(20 * time.Millisecond)
	if err := c.Button(ctx, ButtonSelect, false); err != nil {
		return err
	}
	return c.Touch(ctx, int(touchpadWidth), int(touchpadHeight), TouchClick)
}
