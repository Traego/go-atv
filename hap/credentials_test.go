package hap

import (
	"bytes"
	"testing"
)

// pyatv's test credentials, so the formats are known to agree.
const pyatvCredentials = "E734EA6C2B6257DE72355E472AA05A4C487E6B463C029ED306DF2F01B5636B58:" +
	"80FD8265B0748DA90BC5C5294DABE394D3D47199994AE96AC73EE45C783537B1:" +
	"35443739374644332D333533382D343237452D413437422D41333246433643463" +
	"3413641:34443739374644332D333533382D343237452D413437422D413332464" +
	"336434633413641"

func TestParseCredentials(t *testing.T) {
	c, err := ParseCredentials(pyatvCredentials)
	if err != nil {
		t.Fatal(err)
	}
	if string(c.DeviceID) != "5D797FD3-3538-427E-A47B-A32FC6CF3A6A" {
		t.Errorf("device id %q", c.DeviceID)
	}
	if string(c.ClientID) != "4D797FD3-3538-427E-A47B-A32FC6CF3A6A" {
		t.Errorf("client id %q", c.ClientID)
	}
	if len(c.LTPK) != 32 || len(c.LTSK) != 32 {
		t.Errorf("key sizes %d %d", len(c.LTPK), len(c.LTSK))
	}
	back, err := ParseCredentials(c.String())
	if err != nil || !bytes.Equal(back.LTPK, c.LTPK) || !bytes.Equal(back.ClientID, c.ClientID) {
		t.Fatalf("round trip: %v %v", err, back)
	}
}

func TestParseCredentialsRejectsBadInput(t *testing.T) {
	for _, s := range []string{"", "a:b", "zz:zz:zz:zz", "00:00:00:00"} {
		if _, err := ParseCredentials(s); err == nil {
			t.Errorf("%q: want error", s)
		}
	}
}
