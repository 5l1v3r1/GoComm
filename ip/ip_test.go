package ip

import "testing"

func TestIPv4(t *testing.T) {
	data := []byte{4, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0}

	p, err := NewIPv4Packet(data)
	if err != nil {
		t.Fatalf("Error creating new packet: %v", err)
	}
	t.Logf("NewIPv4Packet()")
	if p.Version != IPv4 {
		t.Fatalf("Version should be IPv4, instead found %d", p.Version)
	}

	t.Logf("Version: %d", p.Version)

	t.Log("---")

}

func TestVersion(t *testing.T) {
	data := []byte{4, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0}

	v := GetVersion(data)
	if v != 4 {
		t.Fatalf("Version returned should be 4")
	}
}
