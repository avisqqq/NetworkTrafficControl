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
	Proto     string `json:"proto"`
	Action    string `json:"action"`
	Direction string `json:"direction"`
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
