package maps_test

import (
	"ntc/source/domain/packet"
	"ntc/source/infrastructure/packet/maps"
)

// Compile-time contract check — if IpMap is missing any method from
// packet.Map[packet.IPEntry], this file will not compile.
var _ packet.Map[packet.IPEntry] = (*maps.IpMap)(nil)
