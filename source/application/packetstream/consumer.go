package packetstream

import "ntc/source/domain/packet"

type Consumer interface {
	Consume(packet.Packet)
}
