package http

type IpRequest struct {
	IP string `json:"ip"`
}

type IpResponse struct {
	OK      bool   `json:"ok"`
	IP      string `json:"ip"`
	Version uint8  `json:"version"`
}

type PacketEvent struct {
	Seq       uint64 `json:"seq"`
	Src       string `json:"src"`
	Dst       string `json:"dst"`
	Proto     uint8  `json:"proto"`
	Action    uint8  `json:"action"`
	Direction uint8  `json:"direction"`
}
