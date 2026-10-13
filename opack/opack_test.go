package opack

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Each case is a value, its encoding, and what decoding gives back. The
// encodings come from pyatv's tests and from Apple's encoder on macOS.
var cases = []struct {
	name    string
	value   any
	hex     string
	decoded any
}{
	{"true", true, "01", true},
	{"false", false, "02", false},
	{"nil", nil, "04", nil},
	{"uuid", UUID{0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78},
		"0512345678123456781234567812345678", UUID{0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78}},
	{"date 2001-01-02", time.Date(2001, 1, 2, 0, 0, 0, 0, time.UTC), "06000000000018f540", time.Date(2001, 1, 2, 0, 0, 0, 0, time.UTC)},
	{"zero", 0, "08", int64(0)},
	{"15", 0xF, "17", int64(15)},
	{"39", 0x27, "2f", int64(39)},
	{"40", 0x28, "3028", int64(40)},
	{"127", int8(127), "307f", int64(127)},
	{"128 takes two bytes, the width is signed", 128, "318000", int64(128)},
	{"-1", -1, "07", int64(-1)},
	{"-5", -5, "30fb", int64(-5)},
	{"-128", -128, "3080", int64(-128)},
	{"-129", -129, "317fff", int64(-129)},
	{"-300", -300, "31d4fe", int64(-300)},
	{"0x1ff", 0x1FF, "31ff01", int64(0x1FF)},
	{"32768", 32768, "3200800000", int64(32768)},
	{"0x1ffffff", 0x1FFFFFF, "32ffffff01", int64(0x1FFFFFF)},
	{"2^31", int64(1) << 31, "330000008000000000", int64(1) << 31},
	{"0xffffffff", uint32(0xFFFFFFFF), "33ffffffff00000000", int64(0xFFFFFFFF)},
	{"0x1ffffffffffffff", int64(0x1FFFFFFFFFFFFFF), "33ffffffffffffff01", int64(0x1FFFFFFFFFFFFFF)},
	{"float64", 1.0, "36000000000000f03f", 1.0},
	{"float32", float32(1.0), "350000803f", float32(1.0)},
	{"empty string", "", "40", ""},
	{"a", "a", "4161", "a"},
	{"abc", "abc", "43616263", "abc"},
	{"32 chars", strings.Repeat("a", 32), "60" + strings.Repeat("61", 32), strings.Repeat("a", 32)},
	{"33 chars", strings.Repeat("a", 33), "6121" + strings.Repeat("61", 33), strings.Repeat("a", 33)},
	{"256 chars", strings.Repeat("a", 256), "620001" + strings.Repeat("61", 256), strings.Repeat("a", 256)},
	{"65536 chars", strings.Repeat("a", 65536), "6300000100" + strings.Repeat("61", 65536), strings.Repeat("a", 65536)},
	{"one byte", []byte{0xac}, "71ac", []byte{0xac}},
	{"three bytes", []byte{0x12, 0x34, 0x56}, "73123456", []byte{0x12, 0x34, 0x56}},
	{"32 bytes", bytes.Repeat([]byte{0xad}, 32), "90" + strings.Repeat("ad", 32), bytes.Repeat([]byte{0xad}, 32)},
	{"33 bytes", bytes.Repeat([]byte{0x61}, 33), "9121" + strings.Repeat("61", 33), bytes.Repeat([]byte{0x61}, 33)},
	{"256 bytes", bytes.Repeat([]byte{0x61}, 256), "920001" + strings.Repeat("61", 256), bytes.Repeat([]byte{0x61}, 256)},
	{"65536 bytes", bytes.Repeat([]byte{0x61}, 65536), "9300000100" + strings.Repeat("61", 65536), bytes.Repeat([]byte{0x61}, 65536)},
	{"empty array", []any{}, "d0", []any{}},
	{"array", []any{1, "test", false}, "d3094474657374 02", []any{int64(1), "test", false}},
	{"nested array", []any{[]any{true}}, "d1d101", []any{[]any{true}}},
	{"typed slice", []string{"a", "b"}, "d241614162", []any{"a", "b"}},
	{"15 element array is endless", []any{"a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a"},
		"df4161" + strings.Repeat("a0", 14) + "03", []any{"a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a"}},
	{"empty dict", map[string]any{}, "e0", map[string]any{}},
	{"dict", map[string]any{"a": 12, "b": nil}, "e2 4161 14 4162 04", map[string]any{"a": int64(12), "b": nil}},
	{"nested dict", map[string]any{"t": map[string]any{"a": 2}}, "e1 4174 e1 4161 0a", map[string]any{"t": map[string]any{"a": int64(2)}}},
	{"typed map", map[string]int{"n": 3}, "e1416e0b", map[string]any{"n": int64(3)}},
	{"pointer to a string", []any{"a", "a"}, "d2 4161 a0", []any{"a", "a"}},
	{"pointers in order", []any{"foo", "bar", "foo", "bar"}, "d4 43666f6f 43626172 a0 a1", []any{"foo", "bar", "foo", "bar"}},
	{"pointer from inside a nested dict", map[string]any{"a": "b", "c": map[string]any{"d": "a"}, "d": true},
		"e3 4161 4162 4163 e1 4164 a0 a3 01", map[string]any{"a": "b", "c": map[string]any{"d": "a"}, "d": true}},
	{"containers are not in the pointer table", []any{map[string]any{"k": "v"}, map[string]any{"k": "v"}, "zzz", "zzz"},
		"d4 e1416b4176 e1a0a1 437a7a7a a2", []any{map[string]any{"k": "v"}, map[string]any{"k": "v"}, "zzz", "zzz"}},
	{"small ints are not in the pointer table", []any{1, 1, 100, 100, 70000, 70000, 1.5, 1.5, "s", "s"},
		"da 09 09 3064 a0 3270110100 a1 36000000000000f83f a2 4173 a3",
		[]any{int64(1), int64(1), int64(100), int64(100), int64(70000), int64(70000), 1.5, 1.5, "s", "s"}},
}

func TestEncode(t *testing.T) {
	for _, c := range cases {
		got, err := Encode(c.value)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if want := unhex(t, c.hex); !bytes.Equal(got, want) {
			t.Errorf("%s: encoded %s, want %s", c.name, short(got), short(want))
		}
	}
}

func TestDecode(t *testing.T) {
	for _, c := range cases {
		got, rest, err := Decode(unhex(t, c.hex))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if len(rest) != 0 {
			t.Errorf("%s: %d bytes left over", c.name, len(rest))
		}
		if !reflect.DeepEqual(got, c.decoded) {
			t.Errorf("%s: decoded %#v, want %#v", c.name, got, c.decoded)
		}
	}
}

func TestDecodeReturnsTheRest(t *testing.T) {
	v, rest, err := Decode(unhex(t, "4161ff"))
	if err != nil || v != "a" || !bytes.Equal(rest, []byte{0xff}) {
		t.Fatalf("got %v %x %v", v, rest, err)
	}
}

func TestDecodeWidePointers(t *testing.T) {
	// Pointer indexes are 1, 2, 3 and 4 bytes wide for 0xC1 to 0xC4.
	for _, h := range []string{"df30013002c10103", "df30013002c2010003", "df30013002c301000003", "df30013002c40100000003"} {
		v, _, err := Decode(unhex(t, h))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(v, []any{int64(1), int64(2), int64(2)}) {
			t.Errorf("%s: %#v", h, v)
		}
	}
	// Index 40 needs the one-byte form.
	var many []any
	for i := 0; i < 41; i++ {
		many = append(many, strings.Repeat("x", 2)+string(rune('A'+i)))
	}
	many = append(many, many[40])
	enc, err := Encode(many)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(enc, []byte{0xC1, 40, 0x03}) {
		t.Fatalf("tail %x", enc[len(enc)-4:])
	}
	back, _, err := Decode(enc)
	if err != nil || !reflect.DeepEqual(back, many) {
		t.Fatalf("round trip: %v", err)
	}
}

func TestDecodeNullTerminatedString(t *testing.T) {
	v, _, err := Decode(unhex(t, "6f666f6f00"))
	if err != nil || v != "foo" {
		t.Fatalf("got %v %v", v, err)
	}
}

func TestDecodeErrors(t *testing.T) {
	for _, h := range []string{"", "00", "41", "3101", "d1", "e14161", "a0", "df4161", "e101 01"} {
		if _, _, err := Decode(unhex(t, h)); err == nil {
			t.Errorf("%q: want error", h)
		}
	}
}

func TestEncodeErrors(t *testing.T) {
	for _, v := range []any{struct{}{}, map[int]string{1: "a"}, make(chan int)} {
		if _, err := Encode(v); err == nil {
			t.Errorf("%T: want error", v)
		}
	}
}

func TestGoldenSystemInfo(t *testing.T) {
	// pyatv's golden message, through both directions.
	msg := map[string]any{
		"_i":    "_systemInfo",
		"_x":    1254122577,
		"_btHP": false,
		"_c": map[string]any{
			"_pubID": "AA:BB:CC:DD:EE:FF",
			"_sv":    "230.1",
			"_bf":    0,
			"_siriInfo": map[string]any{
				"collectorElectionVersion": 1.0,
				"deviceCapabilities":       map[string]any{"seymourEnabled": 1, "voiceTriggerEnabled": 2},
				"sharedDataProtoBuf":       bytes.Repeat([]byte{8}, 512),
			},
			"_stA":   []any{"com.apple.LiveAudio", "com.apple.siri.wakeup", "com.apple.Seymour", "com.apple.announce", "com.apple.coreduet.sync", "com.apple.SeymourSession"},
			"_i":     "6c62fca18b11",
			"_clFl":  128,
			"_idsID": "44E14ABC-DDDD-4188-B661-11BAAAF6ECDE",
			"_hkUID": []any{UUID{0x17, 0xed, 0x16, 0x0a, 0x81, 0xf8, 0x44, 0x88, 0x96, 0x2c, 0x6b, 0x1a, 0x83, 0xeb, 0x00, 0x81}},
			"_dC":    "1",
			"_sf":    256,
			"model":  "iPhone10,6",
			"name":   "iPhone",
		},
		"_t": 2,
	}
	enc, err := Encode(msg)
	if err != nil {
		t.Fatal(err)
	}
	back, rest, err := Decode(enc)
	if err != nil || len(rest) != 0 {
		t.Fatal(err, len(rest))
	}
	got := back.(map[string]any)
	if got["_x"] != int64(1254122577) || got["_c"].(map[string]any)["_clFl"] != int64(128) {
		t.Fatalf("%#v", got)
	}
	again, err := Encode(back)
	if err != nil || !bytes.Equal(again, enc) {
		t.Fatal("re-encoding differs")
	}
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func short(b []byte) string {
	if len(b) > 40 {
		return hex.EncodeToString(b[:40]) + "..."
	}
	return hex.EncodeToString(b)
}
