package http

import (
	"ntc/source/domain/packet"
)

type ListManager interface {
	AddToBlackListByString(ip string) (packet.IPKey, error)
	RemoveFromBlackListByString(ip string) (packet.IPKey, error)
	GetFromBlackListByString() ([]packet.IPEntry, error)
	AddToWhiteListByString(ip string) (packet.IPKey, error)
	RemoveFromWhiteListByString(ip string) (packet.IPKey, error)
	GetFromWhiteListByString() ([]packet.IPEntry, error)
}
