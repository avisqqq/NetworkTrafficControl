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
	OK        bool   `json:"ok"`
	CIDR      string `json:"cidr"`
	PrefixLen uint32 `json:"prefix_len,omitempty"`
	Version   uint8  `json:"version"`
}
type PacketEvent struct {
	Time      string `json:"time"`
	Seq       uint64 `json:"seq"`
	Src       string `json:"src"`
	Dst       string `json:"dst"`
	SrcPort   uint16 `json:"src_port"`
	DstPort   uint16 `json:"dst_port"`
	PktSize   uint16 `json:"pkt_size"`
	Proto     string `json:"proto"`
	Action    string `json:"action"`
	IPVersion uint8  `json:"ip_version"`
	Direction string `json:"direction"`
	TCPFlags  uint8  `json:"tcp_flags"`
}

type AppLogResponse struct {
	ID           uint64 `json:"id"`
	CreatedAt    string `json:"created_at"`
	Level        string `json:"level"`
	Category     string `json:"category"`
	Event        string `json:"event"`
	Message      string `json:"message"`
	EntityType   string `json:"entity_type"`
	EntityID     string `json:"entity_id"`
	Actor        string `json:"actor"`
	Source       string `json:"source"`
	MetadataJSON string `json:"metadata_json"`
}
