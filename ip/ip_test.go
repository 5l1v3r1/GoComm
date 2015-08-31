package ip

import (
	"./dscp"
	"./ecn"
	"testing"
)

var validIPv4Packet = []byte{
	0x54, 0xB9, 0x00, 0x14,
	0x13, 0x37, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
}

var validIPv6Packet = []byte{
	0x56, 0xB9, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
}

// IHL is too short for a valid packet.
var shortIHL = []byte{
	0x44, 0xB9, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
}

// IHL is too long for the total length of the packet.
var largeIHL = []byte{
	0xF4, 0xB9, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
}

// Total Length value is wrong.
var wrongTL = []byte{
	0x54, 0xB9, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
}

func TestIPv4(t *testing.T) {
	// Test with a valid IPv4 packet.
	p, err := NewIPv4Packet(validIPv4Packet)
	if err != nil {
		t.Fatalf("*** Error creating new packet: %v", err)
	}
	t.Logf("NewIPv4Packet()")
	if p.Version != IPv4 {
		t.Fatalf("*** Version should be IPv4, instead found %d", p.Version)
	}
	t.Logf("Version: %d", p.Version)

	if p.IHL != MinIHL {
		t.Fatalf("*** IHL should be %d, instead found %d", MinIHL, p.IHL)
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

	if p.TotalLength != len(validIPv4Packet) {
		t.Fatalf("*** Total Length should be %d, instead found %d", len(validIPv4Packet), p.TotalLength)
	}
	t.Logf("Total Length: %d", p.TotalLength)

	if p.Identification != 0x1337 {
		t.Fatalf("*** Identification should be %d, instead found %d", 0x1337, p.Identification)
	}
	t.Logf("Identification: %d", p.Identification)

	t.Log("---")
	t.Log("")

	// Test for various failure cases.
	// At least one for each possible error thrown.
	t.Log("Failing Cases")

	// Test for short packets.
	short := []byte{0, 0, 0, 0, 0}
	p, err = NewIPv4Packet(short)
	if err == nil {
		t.Fatal("*** Expected Packet Too Short error")
	}
	t.Log("Expecting packet too short error")
	t.Logf("Error: %s", err.Error())

	// Test for wrong version.
	p, err = NewIPv4Packet(validIPv6Packet)
	if err == nil {
		t.Logf("p.Version is set to: %d", p.Version)
		t.Fatal("*** Expected non-IPv4 error")
	}
	t.Log("Expecting non-IPv4 error")
	t.Logf("Error: %s", err.Error())

	// Test for invalid IHL that is too small.
	p, err = NewIPv4Packet(shortIHL)
	if err == nil {
		t.Fatal("*** Expected short IHL value error")
	}
	t.Log("Expecting short IHL error")
	t.Logf("Error: %s", err.Error())

	// Test for invalid IHL that is too large.
	p, err = NewIPv4Packet(largeIHL)
	if err == nil {
		t.Fatal("*** Expected large IHL value error")
	}
	t.Log("Expecting large IHL error")
	t.Logf("Error: %s", err.Error())

	// Test for invalid Total Length
	p, err = NewIPv4Packet(wrongTL)
	if err == nil {
		t.Fatal("*** Expected invalid Total Length error")
	}
	t.Log("Expecting invalid Total Length error")
	t.Logf("Error: %s", err.Error())

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
