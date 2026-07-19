package packet

import (
	"fmt"
	"strings"
)

type Direction uint8

const (
	DirIngress Direction = 0
	DirEgress  Direction = 1
)

func ParseDirection(dir uint8) string {
	switch dir {
	case uint8(DirIngress):
		return "INGRESS"
	case uint8(DirEgress):
		return "EGRESS"
	default:
		return "UNKNOWN"
	}
}

func DirectionFromString(value string) (Direction, error) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "INGRESS":
		return DirIngress, nil
	case "EGRESS":
		return DirEgress, nil
	default:
		return 0, fmt.Errorf(
			"unsupported direction %q",
			value,
		)
	}
}
