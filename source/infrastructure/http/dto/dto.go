package dto 

type IpRequest struct {
	IP string `json:"ip"`
}

type IpResponse struct {
	OK      bool   `json:"ok"`
	IP      string `json:"ip"`
	Version uint8  `json:"version"`
}
type CidrRequest struct {
	CIDR string `json:"cidr"`
}

type CidrResponse struct {
	OK      bool   `json:"ok"`
	CIDR    string `json:"cidr"`
	PrefixLen uint32 `json:"prefix_len,omitempty"`
	Version uint8  `json:"version"`
}
type PacketEvent struct {
	Time string `json:"time"`
	Seq       uint64 `json:"seq"`
	Src       string `json:"src"`
	Dst       string `json:"dst"`
	Proto     string`json:"proto"`
	Action    string  `json:"action"`
	Direction string  `json:"direction"`
}
