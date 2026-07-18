package lists

import (
	"ntc/source/domain/network"
	"ntc/source/domain/packet"
)

type ListManager interface {
	AddToBlackListByString(ip string) (packet.IPKey, error)
	RemoveFromBlackListByString(ip string) (packet.IPKey, error)
	GetFromBlackListByString() ([]packet.IPEntry, error)
	AddToWhiteListByString(ip string) (packet.IPKey, error)
	RemoveFromWhiteListByString(ip string) (packet.IPKey, error)
	GetFromWhiteListByString() ([]packet.IPEntry, error)
	AddToOnlyLocalByString(ip string) (packet.IPKey, error)
	RemoveFromOnlyLocalByString(ip string) (packet.IPKey, error)
	GetFromOnlyLocalByString() ([]packet.IPEntry, error)
	AddToLocalNetsV4(ip string) (network.CIDR, error)
	RemoveFromLocalNetsV4(ip string) (network.CIDR, error)
	GetFromLocalNetsV4() ([]network.CIDREntry, error)
	AddToLocalNetsV6(ip string) (network.CIDR, error)
	RemoveFromLocalNetsV6(ip string) (network.CIDR, error)
	GetFromLocalNetsV6() ([]network.CIDREntry, error)
}
