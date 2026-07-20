package maps_test

import (
	"ntc/source/domain/packet"
	"ntc/source/domain/packet/core"
	"ntc/source/infrastructure/packet/maps"
)

// Compile-time contract check — if IpMap is missing any method from
// packet.Map[packet.IPEntry], this file will not compile.
var _ core.Map[packet.IPKey] = (*maps.IpMap)(nil)
