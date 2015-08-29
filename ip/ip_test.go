package ip

import (
	"./dscp"
	"./ecn"
	"testing"
)

func TestIPv4(t *testing.T) {
	data := []byte{0x54, 0xB9, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0}

	p, err := NewIPv4Packet(data)
	if err != nil {
		t.Fatalf("*** Error creating new packet: %v", err)
	}
	t.Logf("NewIPv4Packet()")
	if p.Version != IPv4 {
		t.Fatalf("*** Version should be IPv4, instead found %d", p.Version)
	}
	t.Logf("Version: %d", p.Version)

	if p.IHL != MinIHL {
		t.Fatalf("*** IHL should be 5, instead found %d", p.IHL)
	}
	t.Logf("IHL: %d", p.IHL)

	if p.DSCP != dscp.EF_PHB {
		t.Fatalf("*** DSCP should be %d, instead found %d", dscp.EF_PHB, p.DSCP)
	}
	t.Logf("DSCP: %d", p.DSCP)

	if p.ECN != ecn.ECT1 {
		t.Fatalf("*** ECN should be %d, instead found %d", ecn.ECT1, p.ECN)
	}
	t.Logf("ECN: %d", p.ECN)

	t.Log("---")
	t.Log("")
	t.Log("Failing Cases")

	// Test for short packets.
	data = []byte{0}
	p, err = NewIPv4Packet(data)
	if err == nil {
		t.Fatal("*** Expected Packet Too Short error")
	}
	t.Log(err)

	// Test for wrong version.
	data = []byte{0x56, 0xB9, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0}
	p, err = NewIPv4Packet(data)
	if err == nil {
		t.Logf("p.Version is set to: %d", p.Version)
		t.Fatal("*** Expected non-IPv4 error")
	}
	t.Log(err)

	// Test for invalid IHL.
	data = []byte{0x44, 0xB9, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0}
	p, err = NewIPv4Packet(data)
	if err == nil {
		t.Fatal("*** Expected invalid IHL value error")
	}
	t.Log(err)

}

func TestVersion(t *testing.T) {
	// Test for IPv4
	data := []byte{4, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0}
	v := GetVersion(data)
	if v != 4 {
		t.Fatalf("***Version returned should be 4")
	}

	// Test for IPv6
	data = []byte{6, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0}
	v = GetVersion(data)
	if v != 6 {
		t.Fatalf("*** Version returned should be 6")
	}

	// Test for short packet.
	data = []byte{0}
	v = GetVersion(data)
	if v != -1 {
		t.Fatalf("*** Expected failure from too short of a packet")
	}

	// Test for invalid version
	data = []byte{0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0}
	v = GetVersion(data)
	if v != -1 {
		t.Fatalf("*** Expected failure from invalid version")
	}

}
