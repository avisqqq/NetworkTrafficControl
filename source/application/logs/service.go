package logs

import (
	"context"
	"encoding/json"
	"ntc/source/application/inspection"
	"ntc/source/application/reports"
	domain "ntc/source/domain/logs"
	"strconv"
	"time"
)

type Service struct {
	repo Repository
}

func NewService(repo Repository) *Service {
	return &Service{repo: repo}
}

func (s *Service) Add(ctx context.Context, log domain.AppLog) (domain.AppLog, error) {
	if log.CreatedAt.IsZero() {
		log.CreatedAt = time.Now().UTC()
	}
	return s.repo.Add(ctx, log)
}

func (s *Service) Get(ctx context.Context, filter Filter) ([]domain.AppLog, error) {
	return s.repo.Get(ctx, filter)
}

func (s *Service) Info(ctx context.Context, category domain.Category, event domain.Event, message string) {
	_, _ = s.Add(ctx, domain.AppLog{
		Level:    domain.LevelInfo,
		Category: category,
		Event:    event,
		Message:  message,
	})
}

func (s *Service) Warn(ctx context.Context, category domain.Category, event domain.Event, message string) {
	_, _ = s.Add(ctx, domain.AppLog{
		Level:    domain.LevelWarn,
		Category: category,
		Event:    event,
		Message:  message,
	})
}
func (s *Service) Error(ctx context.Context, category domain.Category, event domain.Event, message string) {
	_, _ = s.Add(ctx, domain.AppLog{
		Level:    domain.LevelError,
		Category: category,
		Event:    event,
		Message:  message,
	})
}

func (s *Service) ServiceStarted(ctx context.Context) {
	_, _ = s.Add(ctx, domain.AppLog{
		Level:    domain.LevelInfo,
		Category: domain.CategorySystem,
		Event:    domain.EventServiceStarted,
		Message:  "service started",
		Actor:    domain.ActorSystem,
		Source:   domain.SourceStartup,
	})
}

func (s *Service) ConfigLoaded(ctx context.Context) {
	_, _ = s.Add(ctx, domain.AppLog{
		Level:    domain.LevelInfo,
		Category: domain.CategorySystem,
		Event:    domain.EventConfigLoaded,
		Message:  "config loaded",
		Actor:    domain.ActorSystem,
		Source:   domain.SourceStartup,
	})
}

func (s *Service) ListActionSucceeded(ctx context.Context, list, action, value string) {
	_, _ = s.Add(ctx, domain.AppLog{
		Level:      domain.LevelInfo,
		Category:   domain.CategoryList,
		Event:      listEvent(list, action),
		Message:    action + " " + list + ": " + value,
		EntityType: entityTypeForList(list),
		EntityID:   value,
		Actor:      domain.ActorAPI,
		Source:     domain.SourceListManager,
	})
}

func (s *Service) ListActionFailed(ctx context.Context, list, action, value string, err error) {
	if err == nil {
		return
	}

	_, _ = s.Add(ctx, domain.AppLog{
		Level:      domain.LevelWarn,
		Category:   domain.CategoryList,
		Event:      listEvent(list, action),
		Message:    action + " " + list + " failed: " + err.Error(),
		EntityType: entityTypeForList(list),
		EntityID:   value,
		Actor:      domain.ActorAPI,
		Source:     domain.SourceListManager,
	})
}

func (s *Service) StorageError(ctx context.Context, operation string, err error) {
	if err == nil {
		return
	}

	_, _ = s.Add(ctx, domain.AppLog{
		Level:    domain.LevelError,
		Category: domain.CategoryStorage,
		Event:    domain.EventStorageError,
		Message:  operation + ": " + err.Error(),
		Actor:    domain.ActorSystem,
		Source:   domain.SourceStorage,
	})
}

func (s *Service) APIError(ctx context.Context, method, path string, status int, message string) {
	_, _ = s.Add(ctx, domain.AppLog{
		Level:    domain.LevelWarn,
		Category: domain.CategorySystem,
		Event:    domain.EventAPIError,
		Message:  method + " " + path + ": " + message,
		Actor:    domain.ActorAPI,
		Source:   domain.SourceHTTP,
	})
}

func (s *Service) PacketInspectRequested(ctx context.Context, req inspection.PacketRequest) {
	_, _ = s.Add(ctx, domain.AppLog{
		Level:      domain.LevelInfo,
		Category:   domain.CategoryInspect,
		Event:      domain.EventPacketInspectRequested,
		Message:    "packet inspect requested",
		EntityType: domain.EntityTypePacket,
		EntityID:   strconv.FormatUint(req.Seq, 10),
		Actor:      domain.ActorAPI,
		Source:     domain.SourceInspection,
		MetadataJSON: metadataJSON(map[string]any{
			"seq":       req.Seq,
			"src":       req.Src,
			"dst":       req.Dst,
			"src_port":  req.SrcPort,
			"dst_port":  req.DstPort,
			"proto":     req.Proto,
			"action":    req.Action,
			"direction": req.Direction,
		}),
	})
}

func (s *Service) GeoLookupSkipped(ctx context.Context, endpoint, ip string, port uint16, proto, scope string, warn bool) {
	level := domain.LevelInfo
	if warn {
		level = domain.LevelWarn
	}

	message := "geo lookup skipped: " + scope
	if warn && scope == "Public internet" {
		message = "geo lookup skipped: provider not configured"
	}

	_, _ = s.Add(ctx, domain.AppLog{
		Level:      level,
		Category:   domain.CategoryInspect,
		Event:      domain.EventGeoLookupSkipped,
		Message:    message,
		EntityType: domain.EntityTypeIP,
		EntityID:   ip,
		Actor:      domain.ActorAPI,
		Source:     domain.SourceInspection,
		MetadataJSON: metadataJSON(map[string]any{
			"ip":       ip,
			"port":     port,
			"proto":    proto,
			"scope":    scope,
			"endpoint": endpoint,
		}),
	})
}

func (s *Service) GeoLookupFailed(ctx context.Context, endpoint, ip string, port uint16, proto, scope, provider string, err error) {
	if err == nil {
		return
	}

	_, _ = s.Add(ctx, domain.AppLog{
		Level:      domain.LevelWarn,
		Category:   domain.CategoryInspect,
		Event:      domain.EventGeoLookupFailed,
		Message:    "geo lookup failed: " + err.Error(),
		EntityType: domain.EntityTypeIP,
		EntityID:   ip,
		Actor:      domain.ActorAPI,
		Source:     domain.SourceInspection,
		MetadataJSON: metadataJSON(map[string]any{
			"ip":       ip,
			"port":     port,
			"proto":    proto,
			"scope":    scope,
			"endpoint": endpoint,
			"provider": provider,
			"error":    err.Error(),
		}),
	})
}

func (s *Service) GeoLookupSucceeded(ctx context.Context, endpoint, ip string, port uint16, proto, scope string, geo inspection.GeoInfo) {
	_, _ = s.Add(ctx, domain.AppLog{
		Level:      domain.LevelInfo,
		Category:   domain.CategoryInspect,
		Event:      domain.EventGeoLookupSucceeded,
		Message:    "geo lookup succeeded: " + ip,
		EntityType: domain.EntityTypeIP,
		EntityID:   ip,
		Actor:      domain.ActorAPI,
		Source:     domain.SourceInspection,
		MetadataJSON: metadataJSON(map[string]any{
			"ip":           ip,
			"port":         port,
			"proto":        proto,
			"scope":        scope,
			"endpoint":     endpoint,
			"provider":     geo.Provider,
			"country":      geo.Country,
			"country_code": geo.CountryCode,
			"as":           geo.AS,
			"as_name":      geo.ASName,
			"isp":          geo.ISP,
			"proxy":        geo.Proxy,
			"hosting":      geo.Hosting,
			"mobile":       geo.Mobile,
		}),
	})
}

func (s *Service) AIReportRequested(ctx context.Context, hostIP string, limit int, model string) {
	entityID := reportEntityID(hostIP)
	_, _ = s.Add(ctx, domain.AppLog{
		Level:      domain.LevelInfo,
		Category:   domain.CategoryAI,
		Event:      domain.EventAIReportRequested,
		Message:    "ai report requested",
		EntityType: domain.EntityTypeReport,
		EntityID:   entityID,
		Actor:      domain.ActorAPI,
		Source:     domain.SourceAI,
		MetadataJSON: metadataJSON(map[string]any{
			"host_ip": hostIP,
			"scope":   reportScope(hostIP),
			"limit":   limit,
			"model":   model,
		}),
	})
}

func (s *Service) AIReportSucceeded(ctx context.Context, report reports.Report) {
	entityID := reportEntityID(report.Input.HostIP)
	_, _ = s.Add(ctx, domain.AppLog{
		Level:      domain.LevelInfo,
		Category:   domain.CategoryAI,
		Event:      domain.EventAIReportSucceeded,
		Message:    "ai report generated",
		EntityType: domain.EntityTypeReport,
		EntityID:   entityID,
		Actor:      domain.ActorAPI,
		Source:     domain.SourceAI,
		MetadataJSON: metadataJSON(map[string]any{
			"host_ip":      report.Input.HostIP,
			"scope":        report.Input.Scope,
			"limit":        report.Input.Limit,
			"model":        report.Model,
			"duration_ms":  report.DurationMS,
			"generated_at": report.GeneratedAt,
			"response":     json.RawMessage(report.Report),
		}),
	})
}

func (s *Service) AIReportFailed(ctx context.Context, hostIP string, limit int, model string, err error) {
	if err == nil {
		return
	}

	entityID := reportEntityID(hostIP)
	_, _ = s.Add(ctx, domain.AppLog{
		Level:      domain.LevelWarn,
		Category:   domain.CategoryAI,
		Event:      domain.EventAIReportFailed,
		Message:    "ai report failed: " + err.Error(),
		EntityType: domain.EntityTypeReport,
		EntityID:   entityID,
		Actor:      domain.ActorAPI,
		Source:     domain.SourceAI,
		MetadataJSON: metadataJSON(map[string]any{
			"host_ip": hostIP,
			"scope":   reportScope(hostIP),
			"limit":   limit,
			"model":   model,
			"error":   err.Error(),
		}),
	})
}

func metadataJSON(metadata map[string]any) string {
	if len(metadata) == 0 {
		return ""
	}

	data, err := json.Marshal(metadata)
	if err != nil {
		return ""
	}
	return string(data)
}

func reportEntityID(hostIP string) string {
	if hostIP == "" {
		return "global"
	}
	return hostIP
}

func reportScope(hostIP string) string {
	if hostIP == "" {
		return "global"
	}
	return "host"
}

func listEvent(list, action string) domain.Event {
	switch list {
	case "whitelist":
		if action == "add" {
			return domain.EventWhitelistAdded
		}
		return domain.EventWhitelistRemoved
	case "blacklist":
		if action == "add" {
			return domain.EventBlacklistAdded
		}
		return domain.EventBlacklistRemoved
	case "onlylocal":
		if action == "add" {
			return domain.EventOnlyLocalAdded
		}
		return domain.EventOnlyLocalRemoved
	case "localnet_v4", "localnet_v6":
		if action == "add" {
			return domain.EventLocalNetAdded
		}
		return domain.EventLocalNetRemoved
	default:
		return domain.EventAPIError
	}
}

func entityTypeForList(list string) domain.EntityType {
	switch list {
	case "localnet_v4", "localnet_v6":
		return domain.EntityTypeCIDR
	default:
		return domain.EntityTypeIP
	}
}
