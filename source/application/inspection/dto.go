package inspection

type PacketRequest struct {
	Seq       uint64 `json:"seq"`
	Time      string `json:"time"`
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

type PacketResult struct {
	Seq         uint64       `json:"seq"`
	Time        string       `json:"time"`
	Protocol    string       `json:"protocol"`
	Action      string       `json:"action"`
	Direction   string       `json:"direction"`
	IPVersion   uint8        `json:"ip_version"`
	PacketSize  uint16       `json:"packet_size"`
	TCPFlags    uint8        `json:"tcp_flags"`
	Source      EndpointInfo `json:"source"`
	Destination EndpointInfo `json:"destination"`
}

type EndpointInfo struct {
	IP           string  `json:"ip"`
	Port         uint16  `json:"port"`
	Endpoint     string  `json:"endpoint"`
	Scope        string  `json:"scope"`
	Service      string  `json:"service"`
	Geo          GeoInfo `json:"geo"`
	AnalysisHint string  `json:"analysis_hint"`
}

type GeoInfo struct {
	Enabled       bool    `json:"enabled"`
	Provider      string  `json:"provider"`
	Status        string  `json:"status"`
	Message       string  `json:"message"`
	Query         string  `json:"query"`
	Continent     string  `json:"continent"`
	ContinentCode string  `json:"continent_code"`
	Country       string  `json:"country"`
	CountryCode   string  `json:"country_code"`
	Region        string  `json:"region"`
	RegionName    string  `json:"region_name"`
	City          string  `json:"city"`
	District      string  `json:"district"`
	Zip           string  `json:"zip"`
	Latitude      float64 `json:"latitude"`
	Longitude     float64 `json:"longitude"`
	Timezone      string  `json:"timezone"`
	UTCOffset     int     `json:"utc_offset"`
	Currency      string  `json:"currency"`
	ISP           string  `json:"isp"`
	Organization  string  `json:"organization"`
	AS            string  `json:"as"`
	ASName        string  `json:"as_name"`
	Mobile        bool    `json:"mobile"`
	Proxy         bool    `json:"proxy"`
	Hosting       bool    `json:"hosting"`
}
