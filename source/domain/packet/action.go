package packet

type Action uint8

const (
	ActPass Action = iota
	ActDrop
	ActSkip
	ActSSHBypass
	ActOnlyLocalDrop
	ActUnknown
)

func ParseAction(act uint8) Action {
	switch Action(act) {
	case ActPass, ActDrop, ActSkip, ActSSHBypass, ActOnlyLocalDrop:
		return Action(act)
	default:
		return ActUnknown
	}
}

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
	case ActOnlyLocalDrop:
		return "ONLY_LOCAL_DROP"
	default:
		return "UNKNOWN"
	}
}