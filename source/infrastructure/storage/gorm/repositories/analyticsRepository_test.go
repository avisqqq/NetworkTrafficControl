package repositories

import (
	"context"
	"testing"
	"time"

	app "ntc/source/application/analytics"
	"ntc/source/application/inspection"
	"ntc/source/infrastructure/storage/gorm/models"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestAnalyticsRepositorySummaryEmptyDatabase(t *testing.T) {
	repo := NewAnalyticsRepository(testAnalyticsDB(t))

	summary, err := repo.Summary(100)
	if err != nil {
		t.Fatalf("summary: %v", err)
	}

	if len(summary.Peers) != 0 || len(summary.Services) != 0 || len(summary.Countries) != 0 || len(summary.Blocked) != 0 {
		t.Fatalf("expected empty summary rows, got %+v", summary)
	}
	if summary.Totals.Hosts != 0 || summary.Totals.Peers != 0 || summary.Totals.Services != 0 ||
		summary.Totals.Countries != 0 || summary.Totals.Blocked != 0 || summary.Totals.Packets != 0 || summary.Totals.Bytes != 0 {
		t.Fatalf("expected zero totals, got %+v", summary.Totals)
	}
}

func TestAnalyticsRepositoryCountriesUseCurrentEnrichment(t *testing.T) {
	repo := NewAnalyticsRepository(testAnalyticsDB(t))
	seenAt := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)

	if err := repo.RecordPacket(app.PacketStat{
		HostIP:    "192.168.1.10",
		PeerIP:    "149.154.167.222",
		HostScope: "PRIVATE",
		PeerScope: "PUBLIC",
		Proto:     "TCP",
		Port:      443,
		Service:   "HTTPS",
		Direction: "INGRESS",
		Action:    "PASS",
		Packets:   10,
		Bytes:     2048,
		SeenAt:    seenAt,
	}); err != nil {
		t.Fatalf("record packet: %v", err)
	}
	if err := repo.SaveGeo(context.Background(), "149.154.167.222", inspection.GeoInfo{
		Provider:     "test",
		CountryCode:  "NL",
		Organization: "Telegram",
	}); err != nil {
		t.Fatalf("save geo: %v", err)
	}

	summary, err := repo.Summary(100)
	if err != nil {
		t.Fatalf("summary: %v", err)
	}

	if len(summary.Countries) != 1 {
		t.Fatalf("expected one country row, got %+v", summary.Countries)
	}
	if summary.Countries[0].CountryCode != "NL" {
		t.Fatalf("expected enriched country NL, got %+v", summary.Countries[0])
	}
	if summary.Totals.Countries != 1 {
		t.Fatalf("expected one country total, got %+v", summary.Totals)
	}
}

func testAnalyticsDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(
		&models.AnalyticsHost{},
		&models.AnalyticsIP{},
		&models.AnalyticsIPEnrichment{},
		&models.AnalyticsService{},
		&models.HostPeerCounter{},
		&models.HostCountryCounter{},
		&models.HostServiceCounter{},
		&models.BlockedPeerCounter{},
	); err != nil {
		t.Fatalf("migrate db: %v", err)
	}

	return db
}
