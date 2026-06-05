package models

import "time"

type AnalyticsHost struct {
	ID        uint64    `gorm:"primaryKey"`
	IP        string    `gorm:"size:64;not null;uniqueIndex"`
	Hostname  string    `gorm:"size:255"`
	MAC       string    `gorm:"size:64"`
	FirstSeen time.Time `gorm:"not null"`
	LastSeen  time.Time `gorm:"not null;index"`
}

func (AnalyticsHost) TableName() string {
	return "hosts"
}

type AnalyticsIP struct {
	ID        uint64    `gorm:"primaryKey"`
	IP        string    `gorm:"size:64;not null;uniqueIndex"`
	Scope     string    `gorm:"size:64;not null;index"`
	FirstSeen time.Time `gorm:"not null"`
	LastSeen  time.Time `gorm:"not null;index"`
}

func (AnalyticsIP) TableName() string {
	return "ips"
}

type AnalyticsIPEnrichment struct {
	IPID        uint64    `gorm:"primaryKey;column:ip_id"`
	Provider    string    `gorm:"size:64;not null"`
	Country     string    `gorm:"size:128"`
	CountryCode string    `gorm:"size:16;index"`
	Continent   string    `gorm:"size:128"`
	City        string    `gorm:"size:128"`
	Timezone    string    `gorm:"size:128"`
	ASN         string    `gorm:"size:128;index"`
	ASName      string    `gorm:"size:255"`
	ISP         string    `gorm:"size:255"`
	Org         string    `gorm:"size:255"`
	Proxy       bool      `gorm:"not null;default:false;index"`
	Hosting     bool      `gorm:"not null;default:false;index"`
	Mobile      bool      `gorm:"not null;default:false;index"`
	UpdatedAt   time.Time `gorm:"not null;index"`
}

func (AnalyticsIPEnrichment) TableName() string {
	return "ip_enrichment"
}

type AnalyticsService struct {
	ID    uint64 `gorm:"primaryKey"`
	Proto string `gorm:"size:16;not null;uniqueIndex:idx_services_proto_port"`
	Port  uint16 `gorm:"not null;uniqueIndex:idx_services_proto_port"`
	Name  string `gorm:"size:128"`
}

func (AnalyticsService) TableName() string {
	return "services"
}

type HostPeerCounter struct {
	HostIPID  uint64    `gorm:"primaryKey;column:host_ip_id"`
	PeerIPID  uint64    `gorm:"primaryKey;column:peer_ip_id"`
	ServiceID uint64    `gorm:"primaryKey;column:service_id"`
	Direction string    `gorm:"primaryKey;size:16"`
	Action    string    `gorm:"primaryKey;size:32"`
	Packets   uint64    `gorm:"not null;default:0"`
	Bytes     uint64    `gorm:"not null;default:0"`
	FirstSeen time.Time `gorm:"not null"`
	LastSeen  time.Time `gorm:"not null;index"`
}

func (HostPeerCounter) TableName() string {
	return "host_peer_counters"
}

type HostCountryCounter struct {
	HostIPID    uint64 `gorm:"primaryKey;column:host_ip_id"`
	CountryCode string `gorm:"primaryKey;size:16"`
	Direction   string `gorm:"primaryKey;size:16"`
	Action      string `gorm:"primaryKey;size:32"`
	Packets     uint64 `gorm:"not null;default:0"`
	Bytes       uint64 `gorm:"not null;default:0"`
}

func (HostCountryCounter) TableName() string {
	return "host_country_counters"
}

type HostServiceCounter struct {
	HostIPID  uint64 `gorm:"primaryKey;column:host_ip_id"`
	ServiceID uint64 `gorm:"primaryKey;column:service_id"`
	Direction string `gorm:"primaryKey;size:16"`
	Action    string `gorm:"primaryKey;size:32"`
	Packets   uint64 `gorm:"not null;default:0"`
	Bytes     uint64 `gorm:"not null;default:0"`
}

func (HostServiceCounter) TableName() string {
	return "host_service_counters"
}

type BlockedPeerCounter struct {
	HostIPID  uint64    `gorm:"primaryKey;column:host_ip_id"`
	PeerIPID  uint64    `gorm:"primaryKey;column:peer_ip_id"`
	ServiceID uint64    `gorm:"primaryKey;column:service_id"`
	Packets   uint64    `gorm:"not null;default:0"`
	Bytes     uint64    `gorm:"not null;default:0"`
	FirstSeen time.Time `gorm:"not null"`
	LastSeen  time.Time `gorm:"not null;index"`
}

func (BlockedPeerCounter) TableName() string {
	return "blocked_peer_counters"
}
