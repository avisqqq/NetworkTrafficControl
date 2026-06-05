package inspection

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

type GeoProvider interface {
	Lookup(ctx context.Context, ip string) (GeoInfo, error)
}

type Logger interface {
	PacketInspectRequested(ctx context.Context, req PacketRequest)
	GeoLookupSkipped(ctx context.Context, endpoint, ip string, port uint16, proto, scope string, warn bool)
	GeoLookupFailed(ctx context.Context, endpoint, ip string, port uint16, proto, scope, provider string, err error)
	GeoLookupSucceeded(ctx context.Context, endpoint, ip string, port uint16, proto, scope string, geo GeoInfo)
}

type GeoCache interface {
	SaveGeo(ctx context.Context, ip string, geo GeoInfo) error
}

type Service struct {
	provider GeoProvider
	logger   Logger
	cache    GeoCache
}

func NewService(provider GeoProvider, logger Logger, cache GeoCache) *Service {
	return &Service{
		provider: provider,
		logger:   logger,
		cache:    cache,
	}
}

func (s *Service) InspectPacket(ctx context.Context, req PacketRequest) PacketResult {
	if s.logger != nil {
		s.logger.PacketInspectRequested(ctx, req)
	}

	return PacketResult{
		Seq:         req.Seq,
		Time:        req.Time,
		Protocol:    req.Proto,
		Action:      req.Action,
		Direction:   req.Direction,
		IPVersion:   req.IPVersion,
		PacketSize:  req.PktSize,
		TCPFlags:    req.TCPFlags,
		Source:      s.inspectEndpoint(ctx, req.Src, req.SrcPort, req.Proto, true),
		Destination: s.inspectEndpoint(ctx, req.Dst, req.DstPort, req.Proto, false),
	}
}

func (s *Service) inspectEndpoint(ctx context.Context, ip string, port uint16, proto string, source bool) EndpointInfo {
	scope := IPScope(ip)
	geo := GeoInfo{
		Enabled:  false,
		Provider: "none",
		Status:   "skipped",
		Message:  scope,
		Query:    ip,
	}

	if scope != "Public internet" {
		if s.logger != nil {
			s.logger.GeoLookupSkipped(ctx, endpointName(source), ip, port, proto, scope, scope == "Invalid IP")
		}
	} else if s.provider == nil {
		if s.logger != nil {
			s.logger.GeoLookupSkipped(ctx, endpointName(source), ip, port, proto, scope, true)
		}
	} else {
		if data, err := s.provider.Lookup(ctx, ip); err != nil {
			geo = GeoInfo{
				Enabled:  true,
				Provider: "ip-api",
				Status:   "error",
				Message:  err.Error(),
				Query:    ip,
			}
			if s.logger != nil {
				s.logger.GeoLookupFailed(ctx, endpointName(source), ip, port, proto, scope, geo.Provider, err)
			}
		} else {
			geo = data
			if s.cache != nil {
				_ = s.cache.SaveGeo(ctx, ip, geo)
			}
			if s.logger != nil {
				s.logger.GeoLookupSucceeded(ctx, endpointName(source), ip, port, proto, scope, geo)
			}
		}
	}

	return EndpointInfo{
		IP:           ip,
		Port:         port,
		Endpoint:     endpoint(ip, port),
		Scope:        scope,
		Service:      ServiceName(port),
		Geo:          geo,
		AnalysisHint: analysisHint(scope, port, proto, source, geo),
	}
}

func endpointName(source bool) string {
	if source {
		return "source"
	}
	return "destination"
}

func IPScope(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "Invalid IP"
	}

	switch {
	case addr.IsLoopback():
		return "Loopback"
	case addr.IsPrivate():
		return "Private network"
	case addr.IsLinkLocalUnicast():
		return "Link-local"
	case addr.IsMulticast():
		return "Multicast"
	case addr.IsUnspecified():
		return "Unspecified"
	case isReserved(addr):
		return "Reserved"
	default:
		return "Public internet"
	}
}

func ServiceName(port uint16) string {
	services := map[uint16]string{
		20:    "FTP data",
		21:    "FTP",
		22:    "SSH",
		25:    "SMTP",
		53:    "DNS",
		67:    "DHCP server",
		68:    "DHCP client",
		80:    "HTTP",
		110:   "POP3",
		123:   "NTP",
		143:   "IMAP",
		443:   "HTTPS",
		445:   "SMB",
		465:   "SMTPS",
		587:   "SMTP submission",
		993:   "IMAPS",
		995:   "POP3S",
		3000:  "Grafana/dev server",
		8080:  "HTTP alternate",
		8086:  "NTC web/API",
		8428:  "VictoriaMetrics",
		9100:  "Node exporter",
		51820: "WireGuard",
	}

	if port == 0 {
		return "—"
	}
	if service, ok := services[port]; ok {
		return service
	}
	return "Unknown service"
}

func endpoint(ip string, port uint16) string {
	if port == 0 {
		return ip
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

func isReserved(addr netip.Addr) bool {
	if addr.Is4() {
		return strings.HasPrefix(addr.String(), "192.0.2.") ||
			strings.HasPrefix(addr.String(), "198.51.100.") ||
			strings.HasPrefix(addr.String(), "203.0.113.")
	}
	return strings.HasPrefix(addr.String(), "2001:db8:")
}

func analysisHint(scope string, port uint16, proto string, source bool, geo GeoInfo) string {
	parts := []string{scope}
	if port != 0 {
		parts = append(parts, "port "+strconv.Itoa(int(port))+" "+ServiceName(port))
	}
	if proto != "" {
		parts = append(parts, strings.ToUpper(proto))
	}
	if geo.CountryCode != "" {
		parts = append(parts, geo.CountryCode)
	}
	if geo.ASName != "" {
		parts = append(parts, geo.ASName)
	}
	if geo.Proxy {
		parts = append(parts, "proxy/VPN/Tor flag")
	}
	if geo.Hosting {
		parts = append(parts, "hosting/data center flag")
	}
	if source {
		return "Source: " + strings.Join(parts, ", ")
	}
	return "Destination: " + strings.Join(parts, ", ")
}
