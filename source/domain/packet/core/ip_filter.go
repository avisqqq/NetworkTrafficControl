package core

import "ntc/source/domain/packet"

type IpFilter interface {
	AddToWhitelist(entry packet.IPEntry) error
	DeleteFromWhitelist(entry packet.IPEntry) error
	AddToBlacklist(entry packet.IPEntry) error
	DeleteFromBlacklist(entry packet.IPEntry) error

	GetWhitelist() ([]packet.IPEntry, error)
	GetBlacklist() ([]packet.IPEntry, error)
}
