package companion

import (
	"errors"
	"fmt"
	"io"

	"github.com/traego/go-atv/hap"
)

// FrameType is the first byte of a frame.
type FrameType uint8

// The frame types. Only the OPACK and pairing ones are used here.
const (
	FrameNoOp                   FrameType = 0x01
	FramePSStart                FrameType = 0x03
	FramePSNext                 FrameType = 0x04
	FramePVStart                FrameType = 0x05
	FramePVNext                 FrameType = 0x06
	FrameUOpack                 FrameType = 0x07
	FrameEOpack                 FrameType = 0x08
	FramePOpack                 FrameType = 0x09
	FramePAReq                  FrameType = 0x0A
	FramePARsp                  FrameType = 0x0B
	FrameSessionStartRequest    FrameType = 0x10
	FrameSessionStartResponse   FrameType = 0x11
	FrameSessionData            FrameType = 0x12
	FrameFamilyIdentityRequest  FrameType = 0x20
	FrameFamilyIdentityResponse FrameType = 0x21
	FrameFamilyIdentityUpdate   FrameType = 0x22
)

var frameNames = map[FrameType]string{
	FrameNoOp: "NoOp", FramePSStart: "PS_Start", FramePSNext: "PS_Next",
	FramePVStart: "PV_Start", FramePVNext: "PV_Next", FrameUOpack: "U_OPACK",
	FrameEOpack: "E_OPACK", FramePOpack: "P_OPACK", FramePAReq: "PA_Req",
	FramePARsp: "PA_Rsp", FrameSessionStartRequest: "SessionStartRequest",
	FrameSessionStartResponse: "SessionStartResponse", FrameSessionData: "SessionData",
	FrameFamilyIdentityRequest: "FamilyIdentityRequest", FrameFamilyIdentityResponse: "FamilyIdentityResponse",
	FrameFamilyIdentityUpdate: "FamilyIdentityUpdate",
}

func (t FrameType) String() string {
	if n, ok := frameNames[t]; ok {
		return n
	}
	return fmt.Sprintf("FrameType(%#x)", uint8(t))
}

// Frame is one message on the wire.
type Frame struct {
	Type    FrameType
	Payload []byte
}

// maxPayload is what three length bytes can say.
const maxPayload = 1<<24 - 1

// WriteFrame writes f to w. With a cipher, a non-empty payload is sealed
// with the four header bytes as associated data, and the length in the
// header counts the authentication tag.
func WriteFrame(w io.Writer, f Frame, cipher *hap.SessionCipher) error {
	n := len(f.Payload)
	if cipher != nil && n > 0 {
		n += hap.Overhead
	}
	if n > maxPayload {
		return fmt.Errorf("companion: frame of %d bytes is too large", n)
	}
	header := []byte{byte(f.Type), byte(n >> 16), byte(n >> 8), byte(n)}
	payload := f.Payload
	if cipher != nil && len(payload) > 0 {
		payload = cipher.Encrypt(payload, header)
	}
	_, err := w.Write(append(header, payload...))
	return err
}

// ReadFrame reads one frame from r, opening the payload with cipher if one
// is given.
func ReadFrame(r io.Reader, cipher *hap.SessionCipher) (Frame, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return Frame{}, err
	}
	n := int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return Frame{}, err
	}
	if cipher != nil && n > 0 {
		var err error
		if payload, err = cipher.Decrypt(payload, header); err != nil {
			return Frame{}, err
		}
	}
	return Frame{Type: FrameType(header[0]), Payload: payload}, nil
}
