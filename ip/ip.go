package ip

import "errors"

const (
	IPv4 = 4
	IPv6 = 6
)

type IPv4Packet struct {
	Version        int
	IHL            int
	DSCP           int
	ECN            int
	TotalLength    int
	Identification int
	Flags          int
	FragmentOffset int
	TTL            int
	SourceAddr     int
	DestAdder      int
	Data           []byte
}

func GetVersion(data []byte) int {
	// Minimum length of an IP packet is 20 bytes. This is the smallest possible header allowed.
	if len(data) < 20 {
		return -1
	}

	// Check first 4 bits for the version.
	if data[0]&0x4 == 4 {
		return IPv4
	} else if data[0]&0x6 == 6 {
		return IPv6
	} else {
		return -1
	}
}

func NewIPv4Packet(data []byte) (*IPv4Packet, error) {
	// Minimum length of an IP packet is 20 bytes. This is the smallest possible header allowed.
	if len(data) < 20 {
		return nil, errors.New("Packet is too small to be valid.")
	}

	p := &IPv4Packet{}

	// Check first 4 bits for the version.
	if data[0]&0x4 != 4 {
		return nil, errors.New("Not an IPv4 packet.")
	}
	p.Version = IPv4

	return p, nil
}
