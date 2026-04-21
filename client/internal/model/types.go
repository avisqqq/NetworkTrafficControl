package model

type Event struct {
	Ts     uint64
	Seq    uint64
	Src    uint32
	Dst    uint32
	Proto  uint8
	Action uint8
	Pad    [6]byte
}

type OutEvent struct {
	Time   string `json:"time"`
	Seq    uint64 `json:"seq"`
	Src    string `json:"src"`
	Dst    string `json:"dst"`
	Proto  string `json:"proto"`
	Action string `json:"action"`
}

type Action uint8

const (
	ActPass Action = iota
	ActDrop
	ActSkip
	ActSSHBypass
	ActUnknown
)

func (a Action) String() string {
	switch a {
	case ActPass:
		return "PASS"
	case ActDrop:
		return "DROP"
	case ActSkip:
		return "SKIP"
	case ActSSHBypass:
		return "SSH"
	default:
		return "UNKNOWN"
	}
}

func ParseAction(v uint8) Action {
	switch Action(v) {
	case ActPass, ActDrop, ActSkip, ActSSHBypass:
		return Action(v)
	default:
		return ActUnknown
	}
}

func ProtoString(p uint8) string {
	switch p {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return "OTHER"
	}
}
