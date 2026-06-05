package analytics

import "time"

type PacketStat struct {
	HostIP    string
	PeerIP    string
	HostScope string
	PeerScope string
	Proto     string
	Port      uint16
	Service   string
	Direction string
	Action    string
	Packets   uint64
	Bytes     uint64
	SeenAt    time.Time
}

type Summary struct {
	Peers     []PeerSummary    `json:"peers"`
	Services  []ServiceSummary `json:"services"`
	Countries []CountrySummary `json:"countries"`
	Blocked   []BlockedSummary `json:"blocked"`
	Totals    SummaryTotals    `json:"totals"`
}

type SummaryTotals struct {
	Hosts     uint64 `json:"hosts"`
	Peers     uint64 `json:"peers"`
	Services  uint64 `json:"services"`
	Countries uint64 `json:"countries"`
	Blocked   uint64 `json:"blocked"`
	Packets   uint64 `json:"packets"`
	Bytes     uint64 `json:"bytes"`
}

type PeerSummary struct {
	HostIP          string    `json:"host_ip"`
	PeerIP          string    `json:"peer_ip"`
	PeerScope       string    `json:"peer_scope"`
	PeerCountryCode string    `json:"peer_country_code"`
	PeerASN         string    `json:"peer_asn"`
	PeerASName      string    `json:"peer_as_name"`
	PeerISP         string    `json:"peer_isp"`
	PeerOrg         string    `json:"peer_org"`
	PeerProxy       bool      `json:"peer_proxy"`
	PeerHosting     bool      `json:"peer_hosting"`
	PeerMobile      bool      `json:"peer_mobile"`
	Proto           string    `json:"proto"`
	Port            uint16    `json:"port"`
	Service         string    `json:"service"`
	Direction       string    `json:"direction"`
	Action          string    `json:"action"`
	Packets         uint64    `json:"packets"`
	Bytes           uint64    `json:"bytes"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
}

type ServiceSummary struct {
	HostIP    string `json:"host_ip"`
	Proto     string `json:"proto"`
	Port      uint16 `json:"port"`
	Service   string `json:"service"`
	Direction string `json:"direction"`
	Action    string `json:"action"`
	Packets   uint64 `json:"packets"`
	Bytes     uint64 `json:"bytes"`
}

type CountrySummary struct {
	HostIP      string `json:"host_ip"`
	CountryCode string `json:"country_code"`
	Direction   string `json:"direction"`
	Action      string `json:"action"`
	Packets     uint64 `json:"packets"`
	Bytes       uint64 `json:"bytes"`
}

type BlockedSummary struct {
	HostIP          string    `json:"host_ip"`
	PeerIP          string    `json:"peer_ip"`
	PeerCountryCode string    `json:"peer_country_code"`
	PeerASN         string    `json:"peer_asn"`
	PeerASName      string    `json:"peer_as_name"`
	PeerISP         string    `json:"peer_isp"`
	PeerOrg         string    `json:"peer_org"`
	PeerProxy       bool      `json:"peer_proxy"`
	PeerHosting     bool      `json:"peer_hosting"`
	PeerMobile      bool      `json:"peer_mobile"`
	Proto           string    `json:"proto"`
	Port            uint16    `json:"port"`
	Service         string    `json:"service"`
	Packets         uint64    `json:"packets"`
	Bytes           uint64    `json:"bytes"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
}

type Repository interface {
	RecordPacket(stat PacketStat) error
	Summary(limit int) (Summary, error)
	HostSummary(ip string, limit int) (Summary, error)
}
