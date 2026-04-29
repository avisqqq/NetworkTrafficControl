package packet

type Packet struct {
	Ts        uint64
	Seq       uint64
	Src       [16]uint8
	Dst       [16]uint8
	SrcPort   uint16
	DstPort   uint16
	PktSize   uint16
	Proto     uint8
	Action    uint8
	IPVersion uint8
	Direction uint8
	TCPFlags  uint8
	Pad       [1]byte
}
