package packet

type Direction uint8

const (
	DirIngress Direction = 0
	DirEgress  Direction = 1
)

func ParseDirection(dir uint8) string {
	if Direction(dir) == DirEgress {
		return "EGRESS"
	}
	return "INGRESS"
}
