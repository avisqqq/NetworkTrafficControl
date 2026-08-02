package lists

import "ntc/source/domain/packet"

type IpFilter interface {
	AddToWhitelist(entry packet.IPKey) error
	DeleteFromWhitelist(entry packet.IPKey) error
	AddToBlacklist(entry packet.IPKey) error
	DeleteFromBlacklist(entry packet.IPKey) error
	GetWhitelist() ([]packet.IPKey, error)
	GetBlacklist() ([]packet.IPKey, error)
	AddToOnlyLocal(entry packet.IPKey) error
	DeleteFromOnlyLocal(entry packet.IPKey) error
	GetOnlyLocal() ([]packet.IPKey, error)
}
