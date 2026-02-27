package model

type Event struct {
	Ts    uint64
	Seq   uint64
	Src   uint32
	Dst   uint32
	Proto uint8
	Pad   [7]byte
}

type OutEvent struct {
	Ts    uint64 `json:"ts"`
	Seq   uint64 `json:"seq"`
	Src   string `json:"src"`
	Dst   string `json:"dst"`
	Proto uint8  `json:"proto"`
}
