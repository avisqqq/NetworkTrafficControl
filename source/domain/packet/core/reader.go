package core

import "ntc/source/domain/packet"

type Reader interface {
	ReadPackets() <-chan packet.Packet
}
