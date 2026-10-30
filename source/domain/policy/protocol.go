package policy

import (
	"fmt"
	"strings"
)

type Protocol uint8

const (
	ProtocolTCP Protocol = 6
	ProtocolUDP Protocol = 17
)

func ProtocolFromString(value string) (Protocol, error) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "TCP":
		return ProtocolTCP, nil
	case "UDP":
		return ProtocolUDP, nil
	default:
		return 0, fmt.Errorf(
			"unsupported policy protocol %q",
			value,
		)
	}
}

func (p Protocol) String() string {
	switch p {
	case ProtocolTCP:
		return "TCP"
	case ProtocolUDP:
		return "UDP"
	default:
		return "UNKNOWN"
	}
}
