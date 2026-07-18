package packet

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
