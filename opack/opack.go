// Package opack encodes and decodes OPACK, the binary serialization Apple's
// CoreUtils framework uses in the Companion protocol and elsewhere. It is
// compact: booleans, null and small integers take one byte, and an object
// that appears twice is written once and then referred to by its index.
//
// Go values map to OPACK like this. nil, bool, every integer kind, float32,
// float64, string, []byte, time.Time and UUID encode directly; any slice
// encodes as an array and any map with string keys as a dictionary. Decoding
// produces nil, bool, int64, float32, float64, string, []byte, time.Time,
// UUID, []any and map[string]any.
//
// The format is Apple's and undocumented. What is here was checked against
// Apple's own encoder and decoder on macOS, and against pyatv.
package opack

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"time"
)

// UUID is a 16-byte UUID, encoded with tag 0x05.
type UUID [16]byte

// Dates are seconds since 2001-01-01 UTC as a float64, Core Foundation's
// absolute time.
var epoch = time.Date(2001, time.January, 1, 0, 0, 0, 0, time.UTC)

// Encode encodes v. It fails for a value of a kind OPACK cannot carry, such
// as a struct or a map with keys that are not strings.
func Encode(v any) ([]byte, error) {
	e := &encoder{}
	if err := e.encode(v); err != nil {
		return nil, err
	}
	return e.buf, nil
}

type encoder struct {
	buf []byte
	// objs are the encodings of the objects a pointer may refer to, in
	// order. Containers and one-byte values never go in.
	objs [][]byte
}

func (e *encoder) encode(v any) error {
	start := len(e.buf)
	container := false
	switch x := v.(type) {
	case nil:
		e.buf = append(e.buf, 0x04)
	case bool:
		if x {
			e.buf = append(e.buf, 0x01)
		} else {
			e.buf = append(e.buf, 0x02)
		}
	case UUID:
		e.buf = append(e.buf, 0x05)
		e.buf = append(e.buf, x[:]...)
	case time.Time:
		e.buf = append(e.buf, 0x06)
		e.buf = binary.LittleEndian.AppendUint64(e.buf, math.Float64bits(x.Sub(epoch).Seconds()))
	case int:
		e.encodeInt(int64(x))
	case int8:
		e.encodeInt(int64(x))
	case int16:
		e.encodeInt(int64(x))
	case int32:
		e.encodeInt(int64(x))
	case int64:
		e.encodeInt(x)
	case uint:
		e.encodeUint(uint64(x))
	case uint8:
		e.encodeInt(int64(x))
	case uint16:
		e.encodeInt(int64(x))
	case uint32:
		e.encodeInt(int64(x))
	case uint64:
		e.encodeUint(x)
	case float32:
		e.buf = append(e.buf, 0x35)
		e.buf = binary.LittleEndian.AppendUint32(e.buf, math.Float32bits(x))
	case float64:
		e.buf = append(e.buf, 0x36)
		e.buf = binary.LittleEndian.AppendUint64(e.buf, math.Float64bits(x))
	case string:
		e.encodeSized(0x40, 0x60, []byte(x))
	case []byte:
		e.encodeSized(0x70, 0x90, x)
	case []any:
		container = true
		if err := e.encodeArray(len(x), func(i int) any { return x[i] }); err != nil {
			return err
		}
	case map[string]any:
		container = true
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if err := e.encodeDict(keys, func(k string) any { return x[k] }); err != nil {
			return err
		}
	default:
		container = true
		if err := e.encodeReflect(reflect.ValueOf(v)); err != nil {
			return err
		}
	}
	enc := e.buf[start:]
	if container || len(enc) <= 1 {
		return nil
	}
	for i, o := range e.objs {
		if bytes.Equal(o, enc) {
			e.buf = e.buf[:start]
			e.appendPointer(i)
			return nil
		}
	}
	e.objs = append(e.objs, bytes.Clone(enc))
	return nil
}

// encodeInt writes v in the smallest signed width, which is how Apple's
// encoder does it and how Apple's decoder reads it.
func (e *encoder) encodeInt(v int64) {
	switch {
	case v == -1:
		e.buf = append(e.buf, 0x07)
	case v >= 0 && v < 0x28:
		e.buf = append(e.buf, byte(v)+8)
	case v >= math.MinInt8 && v <= math.MaxInt8:
		e.buf = append(e.buf, 0x30, byte(int8(v)))
	case v >= math.MinInt16 && v <= math.MaxInt16:
		e.buf = append(e.buf, 0x31)
		e.buf = binary.LittleEndian.AppendUint16(e.buf, uint16(int16(v)))
	case v >= math.MinInt32 && v <= math.MaxInt32:
		e.buf = append(e.buf, 0x32)
		e.buf = binary.LittleEndian.AppendUint32(e.buf, uint32(int32(v)))
	default:
		e.buf = append(e.buf, 0x33)
		e.buf = binary.LittleEndian.AppendUint64(e.buf, uint64(v))
	}
}

// encodeUint writes v; a value above MaxInt64 goes out as eight raw bytes,
// which the other side will read as negative.
func (e *encoder) encodeUint(v uint64) {
	if v <= math.MaxInt64 {
		e.encodeInt(int64(v))
		return
	}
	e.buf = append(e.buf, 0x33)
	e.buf = binary.LittleEndian.AppendUint64(e.buf, v)
}

// encodeSized writes a string or data: up to 32 bytes with the length in the
// tag, else a tag that says how wide the length field is.
func (e *encoder) encodeSized(short, longBase byte, b []byte) {
	n := len(b)
	switch {
	case n <= 0x20:
		e.buf = append(e.buf, short+byte(n))
	case n <= math.MaxUint8:
		e.buf = append(e.buf, longBase+1, byte(n))
	case n <= math.MaxUint16:
		e.buf = append(e.buf, longBase+2)
		e.buf = binary.LittleEndian.AppendUint16(e.buf, uint16(n))
	case n <= math.MaxUint32:
		e.buf = append(e.buf, longBase+3)
		e.buf = binary.LittleEndian.AppendUint32(e.buf, uint32(n))
	default:
		e.buf = append(e.buf, longBase+4)
		e.buf = binary.LittleEndian.AppendUint64(e.buf, uint64(n))
	}
	e.buf = append(e.buf, b...)
}

func (e *encoder) encodeArray(n int, at func(int) any) error {
	e.buf = append(e.buf, 0xD0+byte(min(n, 0xF)))
	for i := 0; i < n; i++ {
		if err := e.encode(at(i)); err != nil {
			return err
		}
	}
	if n >= 0xF {
		e.buf = append(e.buf, 0x03)
	}
	return nil
}

func (e *encoder) encodeDict(keys []string, at func(string) any) error {
	e.buf = append(e.buf, 0xE0+byte(min(len(keys), 0xF)))
	for _, k := range keys {
		if err := e.encode(k); err != nil {
			return err
		}
		if err := e.encode(at(k)); err != nil {
			return err
		}
	}
	if len(keys) >= 0xF {
		e.buf = append(e.buf, 0x03)
	}
	return nil
}

// encodeReflect handles the slice and map kinds the type switch did not.
func (e *encoder) encodeReflect(rv reflect.Value) error {
	switch rv.Kind() {
	case reflect.Slice, reflect.Array:
		if rv.Kind() == reflect.Slice && rv.IsNil() {
			e.buf = append(e.buf, 0x04)
			return nil
		}
		return e.encodeArray(rv.Len(), func(i int) any { return rv.Index(i).Interface() })
	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			return fmt.Errorf("opack: cannot encode map with %s keys", rv.Type().Key())
		}
		keys := make([]string, 0, rv.Len())
		for _, k := range rv.MapKeys() {
			keys = append(keys, k.String())
		}
		sort.Strings(keys)
		return e.encodeDict(keys, func(k string) any { return rv.MapIndex(reflect.ValueOf(k).Convert(rv.Type().Key())).Interface() })
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			e.buf = append(e.buf, 0x04)
			return nil
		}
		return e.encode(rv.Elem().Interface())
	}
	return fmt.Errorf("opack: cannot encode %s", rv.Type())
}

func (e *encoder) appendPointer(i int) {
	switch {
	case i <= 0x20:
		e.buf = append(e.buf, 0xA0+byte(i))
	case i <= math.MaxUint8:
		e.buf = append(e.buf, 0xC1, byte(i))
	case i <= math.MaxUint16:
		e.buf = append(e.buf, 0xC2, byte(i), byte(i>>8))
	case i <= 0xFFFFFF:
		e.buf = append(e.buf, 0xC3, byte(i), byte(i>>8), byte(i>>16))
	default:
		e.buf = append(e.buf, 0xC4)
		e.buf = binary.LittleEndian.AppendUint32(e.buf, uint32(i))
	}
}

// Decode decodes one value from the front of data and returns it with the
// bytes that follow it.
func Decode(data []byte) (any, []byte, error) {
	d := &decoder{data: data}
	v, err := d.decode()
	if err != nil {
		return nil, nil, err
	}
	return v, data[d.pos:], nil
}

type decoder struct {
	data []byte
	pos  int
	objs []any
}

var errShort = errors.New("opack: data ends inside a value")

func (d *decoder) take(n int) ([]byte, error) {
	if n < 0 || d.pos+n > len(d.data) {
		return nil, errShort
	}
	b := d.data[d.pos : d.pos+n]
	d.pos += n
	return b, nil
}

func (d *decoder) length(width int) (int, error) {
	b, err := d.take(width)
	if err != nil {
		return 0, err
	}
	var n uint64
	for i := width - 1; i >= 0; i-- {
		n = n<<8 | uint64(b[i])
	}
	if n > math.MaxInt32 {
		return 0, fmt.Errorf("opack: length %d is too large", n)
	}
	return int(n), nil
}

func (d *decoder) decode() (any, error) {
	tagb, err := d.take(1)
	if err != nil {
		return nil, err
	}
	tag := tagb[0]
	var v any
	// remember says whether the value joins the table pointers refer to.
	remember := true
	switch {
	case tag == 0x01:
		v, remember = true, false
	case tag == 0x02:
		v, remember = false, false
	case tag == 0x04:
		v, remember = nil, false
	case tag == 0x05:
		b, err := d.take(16)
		if err != nil {
			return nil, err
		}
		var u UUID
		copy(u[:], b)
		v = u
	case tag == 0x06:
		b, err := d.take(8)
		if err != nil {
			return nil, err
		}
		secs := math.Float64frombits(binary.LittleEndian.Uint64(b))
		whole, frac := math.Modf(secs)
		v = epoch.Add(time.Duration(whole)*time.Second + time.Duration(frac*1e9)).UTC()
	case tag == 0x07:
		v, remember = int64(-1), false
	case tag >= 0x08 && tag <= 0x2F:
		v, remember = int64(tag-8), false
	case tag >= 0x30 && tag <= 0x33:
		b, err := d.take(1 << (tag & 0xF))
		if err != nil {
			return nil, err
		}
		switch len(b) {
		case 1:
			v = int64(int8(b[0]))
		case 2:
			v = int64(int16(binary.LittleEndian.Uint16(b)))
		case 4:
			v = int64(int32(binary.LittleEndian.Uint32(b)))
		default:
			v = int64(binary.LittleEndian.Uint64(b))
		}
	case tag == 0x35:
		b, err := d.take(4)
		if err != nil {
			return nil, err
		}
		v = math.Float32frombits(binary.LittleEndian.Uint32(b))
	case tag == 0x36:
		b, err := d.take(8)
		if err != nil {
			return nil, err
		}
		v = math.Float64frombits(binary.LittleEndian.Uint64(b))
	case tag >= 0x40 && tag <= 0x60:
		b, err := d.take(int(tag - 0x40))
		if err != nil {
			return nil, err
		}
		v = string(b)
	case tag >= 0x61 && tag <= 0x64:
		n, err := d.length(1 << (tag - 0x61))
		if err != nil {
			return nil, err
		}
		b, err := d.take(n)
		if err != nil {
			return nil, err
		}
		v = string(b)
	case tag == 0x6F:
		end := bytes.IndexByte(d.data[d.pos:], 0)
		if end < 0 {
			return nil, errShort
		}
		b, _ := d.take(end + 1)
		v = string(b[:end])
	case tag >= 0x70 && tag <= 0x90:
		b, err := d.take(int(tag - 0x70))
		if err != nil {
			return nil, err
		}
		v = bytes.Clone(b)
	case tag >= 0x91 && tag <= 0x94:
		n, err := d.length(1 << (tag - 0x91))
		if err != nil {
			return nil, err
		}
		b, err := d.take(n)
		if err != nil {
			return nil, err
		}
		v = bytes.Clone(b)
	case tag >= 0xA0 && tag <= 0xC0:
		return d.pointer(int(tag - 0xA0))
	case tag >= 0xC1 && tag <= 0xC4:
		// Pointer indexes are one to four bytes wide, unlike string and data
		// lengths, which go one, two, four, eight.
		i, err := d.length(int(tag - 0xC0))
		if err != nil {
			return nil, err
		}
		return d.pointer(i)
	case tag&0xF0 == 0xD0:
		remember = false
		n := int(tag & 0xF)
		out := []any{}
		for i := 0; ; i++ {
			more, err := d.more(n, i)
			if err != nil {
				return nil, err
			}
			if !more {
				break
			}
			item, err := d.decode()
			if err != nil {
				return nil, err
			}
			out = append(out, item)
		}
		v = out
	case tag&0xF0 == 0xE0:
		remember = false
		n := int(tag & 0xF)
		out := map[string]any{}
		for i := 0; ; i++ {
			more, err := d.more(n, i)
			if err != nil {
				return nil, err
			}
			if !more {
				break
			}
			k, err := d.decode()
			if err != nil {
				return nil, err
			}
			key, ok := k.(string)
			if !ok {
				return nil, fmt.Errorf("opack: dictionary key of type %T is not supported", k)
			}
			val, err := d.decode()
			if err != nil {
				return nil, err
			}
			out[key] = val
		}
		v = out
	default:
		return nil, fmt.Errorf("opack: unknown tag %#x", tag)
	}
	if remember && !d.seen(v) {
		d.objs = append(d.objs, v)
	}
	return v, nil
}

// more reports whether a collection with count n, 0xF for endless, has an
// element i. An endless collection ends at a 0x03 byte, which is consumed.
func (d *decoder) more(n, i int) (bool, error) {
	if n != 0xF {
		return i < n, nil
	}
	if d.pos >= len(d.data) {
		return false, errShort
	}
	if d.data[d.pos] == 0x03 {
		d.pos++
		return false, nil
	}
	return true, nil
}

func (d *decoder) pointer(i int) (any, error) {
	if i >= len(d.objs) {
		return nil, fmt.Errorf("opack: pointer to object %d, but only %d seen", i, len(d.objs))
	}
	return d.objs[i], nil
}

// seen reports whether an equal value is already in the table. Apple's
// encoder writes an object once and points at it afterwards, so a repeat is
// not expected; checking keeps the table aligned if one appears.
func (d *decoder) seen(v any) bool {
	for _, o := range d.objs {
		if reflect.DeepEqual(o, v) {
			return true
		}
	}
	return false
}
