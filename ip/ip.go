// This package contains parsing logic for an IP packet.
// Parses IPv4 packets and returns the version if IPv6 is found.
package ip

import (
	"errors"
)

// General constants needed for parsing. Others can be found
// in sub packages such as DSCP and ECN.
const (
	IPv4   = 4
	IPv6   = 6
	MinIHL = 20
)

// This struct is the result of parsing the passed in data into
// a IPv4 version packet.
type IPv4Packet struct {
	Version        int
	IHL            int // Internet Header Length
	DSCP           int // Differentiated Services Code Point
	ECN            int // Explicit Congestion Notification
	TotalLength    int
	Identification int
	Flags          int
	FragmentOffset int
	TTL            int // Time To Live
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
	if data[0]&0x0F == 4 {
		return IPv4
	} else if data[0]&0x0F == 6 {
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
	vrs := GetVersion(data)
	if vrs != IPv4 {
		return nil, errors.New("Not an IPv4 packet.")
	}
	p.Version = vrs

	// Bit shift to the second nibble.
	ihl := int(data[0] >> 4)

	// Internet Header Length is the number of 32-bit words in the header.
	// Convert 32-bit words to bytes
	ihl = ihl * 4

	// Minimum of 20 bytes
	if ihl < 20 {
		return nil, errors.New("IHL is too small for a valid IPv4 packet.")
	}
	// Maximum of total length of the packet
	if ihl > len(data) {
		return nil, errors.New("IHL is too large for a valid IPv4 packet.")
	}
	p.IHL = ihl

	p.DSCP = int(data[1] >> 2)
	p.ECN = int(data[1] & 0x03)

	// Two bytes for a 16bit int
	totalLength := (int(data[2]) << 8) + int(data[3])
	if totalLength != len(data) {
		return nil, errors.New("Total Length does not match actual length of packet.")
	}
	p.TotalLength = totalLength

	// Two bytes for a 16bit int
	p.Identification = (int(data[4]) << 8) + int(data[5])

	return p, nil
}
