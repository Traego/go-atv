package companion

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/traego/go-atv/hap"
	"github.com/traego/go-atv/opack"
)

// Message types, the _t field of an OPACK frame.
const (
	messageEvent    int64 = 1
	messageRequest  int64 = 2
	messageResponse int64 = 3
)

// CommandError is an error the device answered a request with.
type CommandError struct {
	// Code is the device's error code, for example 58822 for a request the
	// device has no handler for.
	Code int64
	// Domain is the error domain, usually RPErrorDomain.
	Domain string
	// Message is the device's text.
	Message string
}

func (e *CommandError) Error() string {
	return fmt.Sprintf("companion: device said %q (%s %d)", e.Message, e.Domain, e.Code)
}

// ErrClosed is returned once the connection is gone.
var ErrClosed = errors.New("companion: connection closed")

// session is one connection: framing, encryption, and the request
// bookkeeping. Pairing and pair-verify run synchronously with handshake,
// while no read loop is running and the cipher may still be changing. Only
// once encryption is settled does start launch the read loop, which from
// then on delivers responses by transaction ID and dispatches events.
type session struct {
	nc     net.Conn
	r      *bufio.Reader
	wmu    sync.Mutex
	cipher atomic.Pointer[hap.SessionCipher]

	mu      sync.Mutex
	xid     int64
	waiters map[int64]chan map[string]any
	started bool
	closed  bool
	err     error
	done    chan struct{}

	onEvent func(name string, content map[string]any)
}

func newSession(nc net.Conn, onEvent func(string, map[string]any)) *session {
	return &session{
		nc:      nc,
		r:       bufio.NewReader(nc),
		xid:     rand.Int64N(1 << 16),
		waiters: map[int64]chan map[string]any{},
		done:    make(chan struct{}),
		onEvent: onEvent,
	}
}

func (s *session) enableEncryption(output, input []byte) error {
	c, err := hap.NewSessionCipher(output, input)
	if err != nil {
		return err
	}
	s.cipher.Store(c)
	return nil
}

// nextXID returns a fresh transaction ID.
func (s *session) nextXID() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	x := s.xid
	s.xid++
	return x
}

// writeFrame sends one frame.
func (s *session) writeFrame(t FrameType, payload []byte) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return WriteFrame(s.nc, Frame{Type: t, Payload: payload}, s.cipher.Load())
}

// sendOPACK encodes msg and sends it as frame type t.
func (s *session) sendOPACK(t FrameType, msg map[string]any) error {
	payload, err := opack.Encode(msg)
	if err != nil {
		return err
	}
	return s.writeFrame(t, payload)
}

// handshake sends a pairing frame and reads the single reply, synchronously,
// before the read loop is running. It is used for pair-setup and pair-verify,
// whose frames carry no transaction ID.
func (s *session) handshake(ctx context.Context, t FrameType, msg map[string]any) (map[string]any, error) {
	if dl, ok := ctx.Deadline(); ok {
		_ = s.nc.SetDeadline(dl)
		defer s.nc.SetDeadline(time.Time{})
	}
	if err := s.sendOPACK(t, msg); err != nil {
		return nil, err
	}
	for {
		f, err := ReadFrame(s.r, s.cipher.Load())
		if err != nil {
			return nil, err
		}
		switch f.Type {
		case FramePSStart, FramePSNext, FramePVStart, FramePVNext:
			resp, ok := decodeMessage(f.Payload)
			if !ok {
				return nil, errors.New("companion: could not decode pairing frame")
			}
			return resp, nil
		case FrameNoOp:
			continue
		default:
			continue
		}
	}
}

// start launches the read loop. It is called once, after any encryption is
// enabled, so the loop never has to change ciphers under itself.
func (s *session) start() {
	s.mu.Lock()
	s.started = true
	s.mu.Unlock()
	go s.readLoop()
}

// request sends msg as an E_OPACK request and waits for the response with the
// same transaction ID. An error the device answers with is returned as a
// CommandError.
func (s *session) request(ctx context.Context, msg map[string]any) (map[string]any, error) {
	xid := s.nextXID()
	msg["_x"] = xid
	msg["_t"] = messageRequest
	ch := make(chan map[string]any, 1)
	s.mu.Lock()
	if s.closed {
		err := s.err
		s.mu.Unlock()
		return nil, err
	}
	s.waiters[xid] = ch
	s.mu.Unlock()
	if err := s.sendOPACK(FrameEOpack, msg); err != nil {
		s.forget(xid)
		return nil, err
	}
	select {
	case resp := <-ch:
		if m, ok := resp["_em"].(string); ok {
			e := &CommandError{Message: m}
			e.Code, _ = resp["_ec"].(int64)
			e.Domain, _ = resp["_ed"].(string)
			return nil, e
		}
		return resp, nil
	case <-ctx.Done():
		s.forget(xid)
		return nil, ctx.Err()
	case <-s.done:
		return nil, s.err
	}
}

// event sends an event, which has no response. Like pyatv, every OPACK frame
// carries a transaction ID even when nothing waits on it; some devices echo
// it back in the event they send in reply.
func (s *session) event(id string, content map[string]any) error {
	return s.sendOPACK(FrameEOpack, map[string]any{"_i": id, "_t": messageEvent, "_c": content, "_x": s.nextXID()})
}

func (s *session) forget(xid int64) {
	s.mu.Lock()
	delete(s.waiters, xid)
	s.mu.Unlock()
}

func (s *session) readLoop() {
	for {
		f, err := ReadFrame(s.r, s.cipher.Load())
		if err != nil {
			s.fail(err)
			return
		}
		switch f.Type {
		case FrameUOpack, FrameEOpack, FramePOpack:
			msg, ok := decodeMessage(f.Payload)
			if !ok {
				continue
			}
			s.dispatch(msg)
		}
	}
}

func (s *session) dispatch(msg map[string]any) {
	switch t, _ := msg["_t"].(int64); t {
	case messageEvent:
		if s.onEvent != nil {
			name, _ := msg["_i"].(string)
			content, _ := msg["_c"].(map[string]any)
			s.onEvent(name, content)
		}
	case messageResponse:
		xid, _ := msg["_x"].(int64)
		s.mu.Lock()
		ch, ok := s.waiters[xid]
		delete(s.waiters, xid)
		s.mu.Unlock()
		if ok {
			ch <- msg
		}
	}
}

func decodeMessage(payload []byte) (map[string]any, bool) {
	v, _, err := opack.Decode(payload)
	if err != nil {
		return nil, false
	}
	msg, ok := v.(map[string]any)
	return msg, ok
}

// fail records why the connection ended and wakes every waiter.
func (s *session) fail(err error) {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		s.err = fmt.Errorf("%w: %w", ErrClosed, err)
		close(s.done)
	}
	s.mu.Unlock()
}

func (s *session) close() error {
	s.fail(errors.New("closed by us"))
	return s.nc.Close()
}
