package companion_test

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/traego/go-atv/companion"
	"github.com/traego/go-atv/companion/companiontest"
	"github.com/traego/go-atv/hap"
)

func newServer(t *testing.T) *companiontest.Server {
	t.Helper()
	s, err := companiontest.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func pairWith(t *testing.T, s *companiontest.Server, pin string) (hap.Credentials, map[string]any, error) {
	t.Helper()
	ctx := testContext(t)
	p, err := companion.StartPairing(ctx, s.Addr(), "test remote")
	if err != nil {
		t.Fatal(err)
	}
	return p.Finish(ctx, pin)
}

func TestPairing(t *testing.T) {
	s := newServer(t)
	creds, info, err := pairWith(t, s, companiontest.PIN)
	if err != nil {
		t.Fatal(err)
	}
	if string(creds.DeviceID) != companiontest.DeviceID {
		t.Errorf("device id %q", creds.DeviceID)
	}
	if info["name"] != "Living Room" || info["model"] != "AppleTV6,2" {
		t.Errorf("device info %v", info)
	}
	if s.State().Pairings != 1 {
		t.Errorf("server counted %d pairings", s.State().Pairings)
	}
	// The credentials survive the text form and open a session.
	back, err := hap.ParseCredentials(creds.String())
	if err != nil {
		t.Fatal(err)
	}
	c, err := companion.Dial(testContext(t), s.Addr(), back, companion.Identity{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
}

func TestPairingWrongPIN(t *testing.T) {
	s := newServer(t)
	_, _, err := pairWith(t, s, "9999")
	var devErr *hap.DeviceError
	if !errors.As(err, &devErr) || devErr.Code != hap.ErrorAuthentication {
		t.Fatalf("got %v", err)
	}
	if s.State().Pairings != 0 {
		t.Error("a pairing was recorded")
	}
}

func TestPairFunction(t *testing.T) {
	s := newServer(t)
	asked := false
	creds, _, err := companion.Pair(testContext(t), s.Addr(), "x", func(context.Context) (string, error) {
		asked = true
		return companiontest.PIN, nil
	})
	if err != nil || !asked || creds.Valid() != nil {
		t.Fatal(err, asked)
	}
}

func dial(t *testing.T, s *companiontest.Server) *companion.Client {
	t.Helper()
	creds, err := s.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	c, err := companion.Dial(testContext(t), s.Addr(), creds, companion.Identity{Name: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestDialSetsUpTheSession(t *testing.T) {
	s := newServer(t)
	dial(t, s)
	st := s.State()
	if st.SystemInfo["name"] != "tester" || st.SystemInfo["model"] != "iPhone10,6" {
		t.Errorf("system info %v", st.SystemInfo)
	}
	if id, _ := st.SystemInfo["_i"].(string); len(id) != 12 {
		t.Errorf("identifier %q", st.SystemInfo["_i"])
	}
	if st.SessionID == 0 {
		t.Error("no session started")
	}
	if st.TVRCProtocolVersion != "1.2" {
		t.Errorf("tv remote session version %q", st.TVRCProtocolVersion)
	}
	// Subscribing is a fire-and-forget event, so wait for the server to see
	// it rather than racing the read.
	if !waitFor(func() bool { return s.State().Interests[companion.EventMediaControls] }) {
		t.Error("not subscribed to media controls")
	}
}

// waitFor polls cond for up to two seconds.
func waitFor(cond func() bool) bool {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

func TestDialRejectsUnknownPairing(t *testing.T) {
	s := newServer(t)
	creds, _ := s.Credentials()
	other := newServer(t)
	// The other device signs pair-verify with a different long-term key, so
	// the client rejects it before trusting anything it says.
	_, err := companion.Dial(testContext(t), other.Addr(), creds, companion.Identity{})
	if err == nil || !strings.Contains(err.Error(), "signature is wrong") {
		t.Fatalf("got %v", err)
	}
}

func TestButtons(t *testing.T) {
	s := newServer(t)
	c := dial(t, s)
	ctx := testContext(t)
	for _, b := range []companion.Button{companion.ButtonUp, companion.ButtonDown, companion.ButtonLeft, companion.ButtonRight, companion.ButtonSelect, companion.ButtonMenu} {
		if err := c.Press(ctx, b); err != nil {
			t.Fatal(b, err)
		}
	}
	if err := c.Hold(ctx, companion.ButtonHome, 10*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	want := []string{"up", "down", "left", "right", "select", "menu", "home"}
	if got := s.State().Presses; !slices.Equal(got, want) {
		t.Errorf("presses %v, want %v", got, want)
	}
	// A release without a press is an error from the device.
	err := c.Button(ctx, companion.ButtonUp, false)
	var cmdErr *companion.CommandError
	if !errors.As(err, &cmdErr) || cmdErr.Domain != "RPErrorDomain" {
		t.Fatalf("got %v", err)
	}
}

func TestPower(t *testing.T) {
	s := newServer(t)
	c := dial(t, s)
	ctx := testContext(t)
	if err := c.TurnOff(ctx); err != nil {
		t.Fatal(err)
	}
	if s.State().PoweredOn {
		t.Error("still on after TurnOff")
	}
	if err := c.TurnOn(ctx); err != nil {
		t.Fatal(err)
	}
	if !s.State().PoweredOn {
		t.Error("still off after TurnOn")
	}
	st, err := c.SystemStatus(ctx)
	if err != nil || st != companion.StatusAwake || !st.On() {
		t.Fatalf("status %v %v", st, err)
	}

	// Status changes arrive as events once subscribed.
	got := make(chan companion.SystemStatus, 1)
	c.Handle(companion.EventSystemStatus, func(content map[string]any) {
		if st, ok := companion.StatusFromEvent(content); ok {
			got <- st
		}
	})
	if err := c.Subscribe(ctx, companion.EventSystemStatus); err != nil {
		t.Fatal(err)
	}
	s.SetStatus(companion.StatusAsleep)
	select {
	case st := <-got:
		if st != companion.StatusAsleep || st.On() {
			t.Errorf("event status %v", st)
		}
	case <-ctx.Done():
		t.Fatal("no status event")
	}

	// Newer tvOS has no handler for the status request.
	s.StatusSupported = false
	_, err = c.SystemStatus(ctx)
	var cmdErr *companion.CommandError
	if !errors.As(err, &cmdErr) || cmdErr.Code != companion.ErrorNoHandler {
		t.Fatalf("got %v", err)
	}
}

func TestAppsAndAccounts(t *testing.T) {
	s := newServer(t)
	s.Apps["com.apple.TVMusic"] = "Music"
	s.Accounts["acc1"] = "Pat"
	c := dial(t, s)
	ctx := testContext(t)
	apps, err := c.Apps(ctx)
	if err != nil || !reflect.DeepEqual(apps, []companion.App{{Name: "Music", BundleID: "com.apple.TVMusic"}}) {
		t.Fatalf("apps %v %v", apps, err)
	}
	if err := c.LaunchApp(ctx, "com.apple.TVMusic"); err != nil {
		t.Fatal(err)
	}
	if err := c.LaunchApp(ctx, "netflix://title/1"); err != nil {
		t.Fatal(err)
	}
	st := s.State()
	if st.ActiveApp != "com.apple.TVMusic" || st.OpenURL != "netflix://title/1" {
		t.Errorf("launched %q %q", st.ActiveApp, st.OpenURL)
	}
	accounts, err := c.Accounts(ctx)
	if err != nil || !reflect.DeepEqual(accounts, []companion.Account{{Name: "Pat", ID: "acc1"}}) {
		t.Fatalf("accounts %v %v", accounts, err)
	}
	if err := c.SwitchAccount(ctx, "acc1"); err != nil || s.State().ActiveAccount != "acc1" {
		t.Fatal(err)
	}
}

func TestMedia(t *testing.T) {
	s := newServer(t)
	c := dial(t, s)
	ctx := testContext(t)
	for _, f := range []func(context.Context) error{c.Play, c.Pause, c.NextTrack, c.PreviousTrack} {
		if err := f(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if got := s.State().MediaCommands; !slices.Equal(got, []string{"play", "pause", "next", "previous"}) {
		t.Errorf("media commands %v", got)
	}
	if err := c.SkipBy(ctx, -4); err != nil || s.State().Position != 6 {
		t.Fatalf("skip: %v, position %v", err, s.State().Position)
	}
	v, err := c.Volume(ctx)
	if err != nil || v != 10 {
		t.Fatalf("volume %v %v", v, err)
	}
	if err := c.SetVolume(ctx, 42); err != nil || s.State().Volume != 42 {
		t.Fatalf("set volume: %v, %v", err, s.State().Volume)
	}
	if err := c.Press(ctx, companion.ButtonVolumeUp); err != nil || s.State().Volume != 47 {
		t.Fatalf("volume up: %v, %v", err, s.State().Volume)
	}
}

func TestTouch(t *testing.T) {
	s := newServer(t)
	c := dial(t, s)
	ctx := testContext(t)
	if err := c.Swipe(ctx, 100, 500, 900, 500, 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := c.Tap(ctx); err != nil {
		t.Fatal(err)
	}
	// Events have no response, so give the server a moment.
	deadline := time.Now().Add(2 * time.Second)
	var touches []companiontest.Touch
	for time.Now().Before(deadline) {
		touches = s.State().Touches
		if len(touches) >= 4 && touches[len(touches)-1].Action == companion.TouchClick {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(touches) < 4 || touches[0].Action != companion.TouchPress || touches[0].X != 100 {
		t.Fatalf("touches %v", touches)
	}
	if rel := touches[len(touches)-2]; rel.Action != companion.TouchRelease || rel.X != 900 {
		t.Errorf("release %v", rel)
	}
	if last := touches[len(touches)-1]; last.Action != companion.TouchClick || last.X != 1000 {
		t.Errorf("click %v", last)
	}
	if got := s.State().Presses; !slices.Equal(got, []string{"select"}) {
		t.Errorf("presses %v", got)
	}
}

func TestRequestTimesOut(t *testing.T) {
	s := newServer(t)
	s.Drop["Slow"] = true
	c := dial(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := c.Request(ctx, "Slow", nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	// The connection is still fine.
	if err := c.Press(testContext(t), companion.ButtonUp); err != nil {
		t.Fatal(err)
	}
}

func TestConnectionLoss(t *testing.T) {
	s := newServer(t)
	c := dial(t, s)
	s.Close()
	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done not closed")
	}
	if !errors.Is(c.Err(), companion.ErrClosed) {
		t.Errorf("err %v", c.Err())
	}
	if _, err := c.Request(testContext(t), "x", nil); !errors.Is(err, companion.ErrClosed) {
		t.Errorf("request after loss: %v", err)
	}
}

func TestCloseStopsTheSession(t *testing.T) {
	s := newServer(t)
	c := dial(t, s)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	st := s.State()
	if st.SessionID != 0 {
		t.Error("session not stopped")
	}
	if st.Interests[companion.EventMediaControls] {
		t.Error("still subscribed")
	}
}
