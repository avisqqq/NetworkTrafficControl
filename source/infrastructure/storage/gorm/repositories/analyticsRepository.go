package repositories

import (
	"context"
	"strings"
	"time"

	app "ntc/source/application/analytics"
	"ntc/source/application/inspection"
	"ntc/source/infrastructure/storage/gorm/models"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type AnalyticsRepository struct {
	db *gorm.DB
}

func NewAnalyticsRepository(db *gorm.DB) *AnalyticsRepository {
	return &AnalyticsRepository{db: db}
}

func (r *AnalyticsRepository) SaveGeo(ctx context.Context, ip string, geo inspection.GeoInfo) error {
	now := time.Now().UTC()
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		row, err := upsertIP(tx, ip, inspection.IPScope(ip), now)
		if err != nil {
			return err
		}

		enrichment := models.AnalyticsIPEnrichment{
			IPID:        row.ID,
			Provider:    geo.Provider,
			Country:     geo.Country,
			CountryCode: geo.CountryCode,
			Continent:   geo.Continent,
			City:        geo.City,
			Timezone:    geo.Timezone,
			ASN:         geo.AS,
			ASName:      geo.ASName,
			ISP:         geo.ISP,
			Org:         geo.Organization,
			Proxy:       geo.Proxy,
			Hosting:     geo.Hosting,
			Mobile:      geo.Mobile,
			UpdatedAt:   now,
		}

		return tx.Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "ip_id"}},
			DoUpdates: clause.Assignments(map[string]any{
				"provider":     enrichment.Provider,
				"country":      enrichment.Country,
				"country_code": enrichment.CountryCode,
				"continent":    enrichment.Continent,
				"city":         enrichment.City,
				"timezone":     enrichment.Timezone,
				"asn":          enrichment.ASN,
				"as_name":      enrichment.ASName,
				"isp":          enrichment.ISP,
				"org":          enrichment.Org,
				"proxy":        enrichment.Proxy,
				"hosting":      enrichment.Hosting,
				"mobile":       enrichment.Mobile,
				"updated_at":   enrichment.UpdatedAt,
			}),
		}).Create(&enrichment).Error
	})
}

func (r *AnalyticsRepository) RecordPacket(stat app.PacketStat) error {
	return r.RecordPackets([]app.PacketStat{stat})
}

func (r *AnalyticsRepository) RecordKnownHost(host app.KnownHost) error {
	if host.IP == "" {
		return nil
	}
	if host.FirstSeen.IsZero() {
		host.FirstSeen = time.Now().UTC()
	}
	if host.LastSeen.IsZero() {
		host.LastSeen = host.FirstSeen
	}

	assignments := map[string]any{
		"last_seen": host.LastSeen,
	}
	if host.Hostname != "" {
		assignments["hostname"] = host.Hostname
	}
	if host.MAC != "" {
		assignments["mac"] = host.MAC
	}

	row := models.AnalyticsHost{
		IP:        host.IP,
		Hostname:  host.Hostname,
		MAC:       host.MAC,
		FirstSeen: host.FirstSeen,
		LastSeen:  host.LastSeen,
	}
	return r.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "ip"}},
		DoUpdates: clause.Assignments(assignments),
	}).Create(&row).Error
}

func (r *AnalyticsRepository) RecordPackets(stats []app.PacketStat) error {
	if len(stats) == 0 {
		return nil
	}

	return r.db.Transaction(func(tx *gorm.DB) error {
		countryCache := make(map[uint64]string)
		for _, stat := range stats {
			if err := r.recordPacketTx(tx, stat, countryCache); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *AnalyticsRepository) recordPacketTx(tx *gorm.DB, stat app.PacketStat, countryCache map[uint64]string) error {
	host, err := upsertIP(tx, stat.HostIP, stat.HostScope, stat.SeenAt)
	if err != nil {
		return err
	}
	if err := upsertHost(tx, stat.HostIP, stat.SeenAt); err != nil {
		return err
	}

	peer, err := upsertIP(tx, stat.PeerIP, stat.PeerScope, stat.SeenAt)
	if err != nil {
		return err
	}

	service, err := upsertService(tx, stat.Proto, stat.Port, stat.Service)
	if err != nil {
		return err
	}

	if err := upsertPeerCounter(tx, host.ID, peer.ID, service.ID, stat); err != nil {
		return err
	}
	if err := upsertServiceCounter(tx, host.ID, service.ID, stat); err != nil {
		return err
	}
	if err := upsertCountryCounter(tx, host.ID, peer, stat, countryCache); err != nil {
		return err
	}
	if stat.Action == "DROP" || stat.Action == "ONLY_LOCAL_DROP" {
		if err := upsertBlockedCounter(tx, host.ID, peer.ID, service.ID, stat); err != nil {
			return err
		}
	}

	return nil
}

func (r *AnalyticsRepository) Summary(limit int) (app.Summary, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	var summary app.Summary
	if err := r.topPeers(limit, &summary.Peers); err != nil {
		return app.Summary{}, err
	}
	if err := r.topServices(limit, &summary.Services); err != nil {
		return app.Summary{}, err
	}
	if err := r.topCountries(limit, &summary.Countries); err != nil {
		return app.Summary{}, err
	}
	if err := r.topBlocked(limit, &summary.Blocked); err != nil {
		return app.Summary{}, err
	}
	if err := r.summaryTotals("", &summary.Totals); err != nil {
		return app.Summary{}, err
	}

	return summary, nil
}

func (r *AnalyticsRepository) HostSummary(ip string, limit int) (app.Summary, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	var summary app.Summary
	if err := r.topPeersForHost(ip, limit, &summary.Peers); err != nil {
		return app.Summary{}, err
	}
	if err := r.topServicesForHost(ip, limit, &summary.Services); err != nil {
		return app.Summary{}, err
	}
	if err := r.topCountriesForHost(ip, limit, &summary.Countries); err != nil {
		return app.Summary{}, err
	}
	if err := r.topBlockedForHost(ip, limit, &summary.Blocked); err != nil {
		return app.Summary{}, err
	}
	if err := r.summaryTotals(ip, &summary.Totals); err != nil {
		return app.Summary{}, err
	}

	return summary, nil
}

func (r *AnalyticsRepository) KnownHosts() ([]app.KnownHost, error) {
	var hosts []app.KnownHost
	err := r.db.Table("hosts").
		Select("ip, hostname, mac, first_seen, last_seen").
		Order("last_seen DESC").
		Scan(&hosts).Error
	return hosts, err
}

func upsertIP(tx *gorm.DB, ip, scope string, seenAt time.Time) (models.AnalyticsIP, error) {
	row := models.AnalyticsIP{
		IP:        ip,
		Scope:     scope,
		FirstSeen: seenAt,
		LastSeen:  seenAt,
	}

	if err := tx.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "ip"}},
		DoUpdates: clause.Assignments(map[string]any{
			"scope":     scope,
			"last_seen": seenAt,
		}),
	}).Create(&row).Error; err != nil {
		return models.AnalyticsIP{}, err
	}

	if row.ID != 0 {
		return row, nil
	}

	if err := tx.Where("ip = ?", ip).First(&row).Error; err != nil {
		return models.AnalyticsIP{}, err
	}
	return row, nil
}

func upsertHost(tx *gorm.DB, ip string, seenAt time.Time) error {
	row := models.AnalyticsHost{
		IP:        ip,
		FirstSeen: seenAt,
		LastSeen:  seenAt,
	}

	return tx.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "ip"}},
		DoUpdates: clause.Assignments(map[string]any{
			"last_seen": seenAt,
		}),
	}).Create(&row).Error
}

func upsertService(tx *gorm.DB, proto string, port uint16, name string) (models.AnalyticsService, error) {
	row := models.AnalyticsService{
		Proto: proto,
		Port:  port,
		Name:  name,
	}

	if err := tx.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "proto"}, {Name: "port"}},
		DoUpdates: clause.Assignments(map[string]any{
			"name": name,
		}),
	}).Create(&row).Error; err != nil {
		return models.AnalyticsService{}, err
	}

	if row.ID != 0 {
		return row, nil
	}

	if err := tx.Where("proto = ? AND port = ?", proto, port).First(&row).Error; err != nil {
		return models.AnalyticsService{}, err
	}
	return row, nil
}

func upsertPeerCounter(tx *gorm.DB, hostID, peerID, serviceID uint64, stat app.PacketStat) error {
	row := models.HostPeerCounter{
		HostIPID:  hostID,
		PeerIPID:  peerID,
		ServiceID: serviceID,
		Direction: stat.Direction,
		Action:    stat.Action,
		Packets:   stat.Packets,
		Bytes:     stat.Bytes,
		FirstSeen: stat.SeenAt,
		LastSeen:  stat.SeenAt,
	}

	return tx.Clauses(clause.OnConflict{
		Columns: counterColumns("host_ip_id", "peer_ip_id", "service_id", "direction", "action"),
		DoUpdates: clause.Assignments(map[string]any{
			"packets":   gorm.Expr("packets + ?", stat.Packets),
			"bytes":     gorm.Expr("bytes + ?", stat.Bytes),
			"last_seen": stat.SeenAt,
		}),
	}).Create(&row).Error
}

func upsertServiceCounter(tx *gorm.DB, hostID, serviceID uint64, stat app.PacketStat) error {
	row := models.HostServiceCounter{
		HostIPID:  hostID,
		ServiceID: serviceID,
		Direction: stat.Direction,
		Action:    stat.Action,
		Packets:   stat.Packets,
		Bytes:     stat.Bytes,
	}

	return tx.Clauses(clause.OnConflict{
		Columns: counterColumns("host_ip_id", "service_id", "direction", "action"),
		DoUpdates: clause.Assignments(map[string]any{
			"packets": gorm.Expr("packets + ?", stat.Packets),
			"bytes":   gorm.Expr("bytes + ?", stat.Bytes),
		}),
	}).Create(&row).Error
}

func upsertCountryCounter(tx *gorm.DB, hostID uint64, peer models.AnalyticsIP, stat app.PacketStat, countryCache map[uint64]string) error {
	countryCode, err := countryCodeForPeer(tx, peer, countryCache)
	if err != nil {
		return err
	}

	row := models.HostCountryCounter{
		HostIPID:    hostID,
		CountryCode: countryCode,
		Direction:   stat.Direction,
		Action:      stat.Action,
		Packets:     stat.Packets,
		Bytes:       stat.Bytes,
	}

	return tx.Clauses(clause.OnConflict{
		Columns: counterColumns("host_ip_id", "country_code", "direction", "action"),
		DoUpdates: clause.Assignments(map[string]any{
			"packets": gorm.Expr("packets + ?", stat.Packets),
			"bytes":   gorm.Expr("bytes + ?", stat.Bytes),
		}),
	}).Create(&row).Error
}

func upsertBlockedCounter(tx *gorm.DB, hostID, peerID, serviceID uint64, stat app.PacketStat) error {
	row := models.BlockedPeerCounter{
		HostIPID:  hostID,
		PeerIPID:  peerID,
		ServiceID: serviceID,
		Packets:   stat.Packets,
		Bytes:     stat.Bytes,
		FirstSeen: stat.SeenAt,
		LastSeen:  stat.SeenAt,
	}

	return tx.Clauses(clause.OnConflict{
		Columns: counterColumns("host_ip_id", "peer_ip_id", "service_id"),
		DoUpdates: clause.Assignments(map[string]any{
			"packets":   gorm.Expr("packets + ?", stat.Packets),
			"bytes":     gorm.Expr("bytes + ?", stat.Bytes),
			"last_seen": stat.SeenAt,
		}),
	}).Create(&row).Error
}

func countryCodeForPeer(tx *gorm.DB, peer models.AnalyticsIP, countryCache map[uint64]string) (string, error) {
	if countryCode := countryCodeForKnownPeer(peer); countryCode != "" {
		return countryCode, nil
	}
	if countryCode, ok := countryCache[peer.ID]; ok {
		return countryCode, nil
	}

	var countryCode string
	if err := tx.Model(&models.AnalyticsIPEnrichment{}).
		Select("country_code").
		Where("ip_id = ?", peer.ID).
		Limit(1).
		Scan(&countryCode).Error; err != nil {
		return "", err
	}
	if countryCode == "" {
		countryCode = "UNKNOWN"
	}
	countryCache[peer.ID] = countryCode
	return countryCode, nil
}

func countryCodeForKnownPeer(peer models.AnalyticsIP) string {
	if peer.IP == "255.255.255.255" || strings.HasSuffix(peer.IP, ".255") {
		return "BROADCAST"
	}
	switch peer.Scope {
	case "Private network":
		return "LOCAL"
	case "Link-local":
		return "LINK_LOCAL"
	case "Multicast":
		return "MULTICAST"
	case "Loopback":
		return "LOOPBACK"
	default:
		return ""
	}
}

func counterColumns(names ...string) []clause.Column {
	columns := make([]clause.Column, 0, len(names))
	for _, name := range names {
		columns = append(columns, clause.Column{Name: name})
	}
	return columns
}

func (r *AnalyticsRepository) summaryTotals(hostIP string, out *app.SummaryTotals) error {
	peerQuery := func() *gorm.DB {
		query := r.db.Table("host_peer_counters hpc").
			Joins("JOIN ips host ON host.id = hpc.host_ip_id")
		if hostIP != "" {
			query = query.Where("host.ip = ?", hostIP)
		}
		return query
	}
	serviceQuery := func() *gorm.DB {
		query := r.db.Table("host_service_counters hsc").
			Joins("JOIN ips host ON host.id = hsc.host_ip_id")
		if hostIP != "" {
			query = query.Where("host.ip = ?", hostIP)
		}
		return query
	}
	countryQuery := func() *gorm.DB {
		query := r.db.Table("host_peer_counters hpc").
			Joins("JOIN ips host ON host.id = hpc.host_ip_id").
			Joins("JOIN ips peer ON peer.id = hpc.peer_ip_id").
			Joins("LEFT JOIN ip_enrichment enr ON enr.ip_id = peer.id")
		if hostIP != "" {
			query = query.Where("host.ip = ?", hostIP)
		}
		return query
	}
	blockedQuery := func() *gorm.DB {
		query := r.db.Table("blocked_peer_counters bpc").
			Joins("JOIN ips host ON host.id = bpc.host_ip_id")
		if hostIP != "" {
			query = query.Where("host.ip = ?", hostIP)
		}
		return query
	}

	if err := peerQuery().Select("COUNT(DISTINCT hpc.host_ip_id)").Scan(&out.Hosts).Error; err != nil {
		return err
	}
	if err := peerQuery().Select("COUNT(DISTINCT hpc.peer_ip_id)").Scan(&out.Peers).Error; err != nil {
		return err
	}
	if err := serviceQuery().Select("COUNT(DISTINCT hsc.service_id)").Scan(&out.Services).Error; err != nil {
		return err
	}
	if err := countryQuery().Select("COUNT(DISTINCT " + countryCodeExpr() + ")").Scan(&out.Countries).Error; err != nil {
		return err
	}
	if err := blockedQuery().Select("COUNT(DISTINCT bpc.peer_ip_id)").Scan(&out.Blocked).Error; err != nil {
		return err
	}
	if err := peerQuery().Select("COALESCE(SUM(hpc.packets), 0)").Scan(&out.Packets).Error; err != nil {
		return err
	}
	if err := peerQuery().Select("COALESCE(SUM(hpc.bytes), 0)").Scan(&out.Bytes).Error; err != nil {
		return err
	}

	return nil
}

func (r *AnalyticsRepository) topPeers(limit int, out *[]app.PeerSummary) error {
	return r.db.Table("host_peer_counters hpc").
		Select(peerSummarySelect("hpc")).
		Joins("JOIN ips host ON host.id = hpc.host_ip_id").
		Joins("JOIN ips peer ON peer.id = hpc.peer_ip_id").
		Joins("LEFT JOIN ip_enrichment enr ON enr.ip_id = peer.id").
		Joins("JOIN services svc ON svc.id = hpc.service_id").
		Order("hpc.bytes DESC").
		Limit(limit).
		Scan(out).Error
}

func (r *AnalyticsRepository) topPeersForHost(ip string, limit int, out *[]app.PeerSummary) error {
	return r.db.Table("host_peer_counters hpc").
		Select(peerSummarySelect("hpc")).
		Joins("JOIN ips host ON host.id = hpc.host_ip_id").
		Joins("JOIN ips peer ON peer.id = hpc.peer_ip_id").
		Joins("LEFT JOIN ip_enrichment enr ON enr.ip_id = peer.id").
		Joins("JOIN services svc ON svc.id = hpc.service_id").
		Where("host.ip = ?", ip).
		Order("hpc.bytes DESC").
		Limit(limit).
		Scan(out).Error
}

func (r *AnalyticsRepository) topServices(limit int, out *[]app.ServiceSummary) error {
	return r.db.Table("host_peer_counters hpc").
		Select(serviceSummarySelect("hpc")).
		Joins("JOIN ips host ON host.id = hpc.host_ip_id").
		Joins("JOIN ips peer ON peer.id = hpc.peer_ip_id").
		Joins("JOIN services svc ON svc.id = hpc.service_id").
		Group("host.ip, svc.proto, svc.port, service, hpc.direction, hpc.action").
		Order("bytes DESC").
		Limit(limit).
		Scan(out).Error
}

func (r *AnalyticsRepository) topServicesForHost(ip string, limit int, out *[]app.ServiceSummary) error {
	return r.db.Table("host_peer_counters hpc").
		Select(serviceSummarySelect("hpc")).
		Joins("JOIN ips host ON host.id = hpc.host_ip_id").
		Joins("JOIN ips peer ON peer.id = hpc.peer_ip_id").
		Joins("JOIN services svc ON svc.id = hpc.service_id").
		Where("host.ip = ?", ip).
		Group("host.ip, svc.proto, svc.port, service, hpc.direction, hpc.action").
		Order("bytes DESC").
		Limit(limit).
		Scan(out).Error
}

func (r *AnalyticsRepository) topCountries(limit int, out *[]app.CountrySummary) error {
	return r.db.Table("host_peer_counters hpc").
		Select(countrySummarySelect()).
		Joins("JOIN ips host ON host.id = hpc.host_ip_id").
		Joins("JOIN ips peer ON peer.id = hpc.peer_ip_id").
		Joins("LEFT JOIN ip_enrichment enr ON enr.ip_id = peer.id").
		Group("host.ip, country_code, hpc.direction, hpc.action").
		Order("bytes DESC").
		Limit(limit).
		Scan(out).Error
}

func (r *AnalyticsRepository) topCountriesForHost(ip string, limit int, out *[]app.CountrySummary) error {
	return r.db.Table("host_peer_counters hpc").
		Select(countrySummarySelect()).
		Joins("JOIN ips host ON host.id = hpc.host_ip_id").
		Joins("JOIN ips peer ON peer.id = hpc.peer_ip_id").
		Joins("LEFT JOIN ip_enrichment enr ON enr.ip_id = peer.id").
		Where("host.ip = ?", ip).
		Group("host.ip, country_code, hpc.direction, hpc.action").
		Order("bytes DESC").
		Limit(limit).
		Scan(out).Error
}

func (r *AnalyticsRepository) topBlocked(limit int, out *[]app.BlockedSummary) error {
	return r.db.Table("blocked_peer_counters bpc").
		Select(blockedSummarySelect("bpc")).
		Joins("JOIN ips host ON host.id = bpc.host_ip_id").
		Joins("JOIN ips peer ON peer.id = bpc.peer_ip_id").
		Joins("LEFT JOIN ip_enrichment enr ON enr.ip_id = peer.id").
		Joins("JOIN services svc ON svc.id = bpc.service_id").
		Order("bpc.bytes DESC").
		Limit(limit).
		Scan(out).Error
}

func (r *AnalyticsRepository) topBlockedForHost(ip string, limit int, out *[]app.BlockedSummary) error {
	return r.db.Table("blocked_peer_counters bpc").
		Select(blockedSummarySelect("bpc")).
		Joins("JOIN ips host ON host.id = bpc.host_ip_id").
		Joins("JOIN ips peer ON peer.id = bpc.peer_ip_id").
		Joins("LEFT JOIN ip_enrichment enr ON enr.ip_id = peer.id").
		Joins("JOIN services svc ON svc.id = bpc.service_id").
		Where("host.ip = ?", ip).
		Order("bpc.bytes DESC").
		Limit(limit).
		Scan(out).Error
}

func peerSummarySelect(table string) string {
	return "host.ip AS host_ip, peer.ip AS peer_ip, peer.scope AS peer_scope, " +
		countryCodeExpr() + " AS peer_country_code, enr.asn AS peer_asn, enr.as_name AS peer_as_name, enr.isp AS peer_isp, enr.org AS peer_org, enr.proxy AS peer_proxy, enr.hosting AS peer_hosting, enr.mobile AS peer_mobile, " +
		"svc.proto AS proto, svc.port AS port, " + serviceDisplayExpr() + " AS service, " + table + ".direction, " + table + ".action, " + table + ".packets, " + table + ".bytes, " + table + ".first_seen, " + table + ".last_seen"
}

func blockedSummarySelect(table string) string {
	return "host.ip AS host_ip, peer.ip AS peer_ip, " +
		countryCodeExpr() + " AS peer_country_code, enr.asn AS peer_asn, enr.as_name AS peer_as_name, enr.isp AS peer_isp, enr.org AS peer_org, enr.proxy AS peer_proxy, enr.hosting AS peer_hosting, enr.mobile AS peer_mobile, " +
		"svc.proto AS proto, svc.port AS port, " + serviceDisplayExpr() + " AS service, " + table + ".packets, " + table + ".bytes, " + table + ".first_seen, " + table + ".last_seen"
}

func serviceSummarySelect(table string) string {
	return "host.ip AS host_ip, svc.proto AS proto, svc.port AS port, " + serviceDisplayExpr() + " AS service, " +
		table + ".direction, " + table + ".action, SUM(" + table + ".packets) AS packets, SUM(" + table + ".bytes) AS bytes"
}

func countrySummarySelect() string {
	return "host.ip AS host_ip, " + countryCodeExpr() + " AS country_code, " +
		"hpc.direction, hpc.action, SUM(hpc.packets) AS packets, SUM(hpc.bytes) AS bytes"
}

func countryCodeExpr() string {
	return "CASE " +
		"WHEN peer.ip = '255.255.255.255' OR peer.ip LIKE '%.255' THEN 'BROADCAST' " +
		"WHEN peer.scope = 'Private network' THEN 'LOCAL' " +
		"WHEN peer.scope = 'Link-local' THEN 'LINK_LOCAL' " +
		"WHEN peer.scope = 'Multicast' THEN 'MULTICAST' " +
		"WHEN peer.scope = 'Loopback' THEN 'LOOPBACK' " +
		"ELSE COALESCE(NULLIF(enr.country_code, ''), 'UNKNOWN') END"
}

func serviceDisplayExpr() string {
	return "CASE " +
		"WHEN svc.name IS NOT NULL AND svc.name NOT IN ('', 'Unknown service') THEN svc.name " +
		"WHEN svc.proto = 'ICMP' THEN 'ICMP' " +
		"WHEN peer.scope IN ('Private network', 'Link-local', 'Loopback') THEN 'Local ' || svc.proto || ' session' " +
		"WHEN peer.scope = 'Multicast' THEN 'Multicast ' || svc.proto || ' traffic' " +
		"WHEN svc.port >= 49152 THEN 'Ephemeral ' || svc.proto || ' session' " +
		"ELSE svc.proto || ' port ' || svc.port END"
}
