package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server      ServerConfig      `yaml:"server"`
	Network     NetworkConfig     `yaml:"network"`
	Persistence PersistenceConfig `yaml:"persistence"`
	AppLogs     AppLogsConfig     `yaml:"app_logs"`
	Geo         GeoConfig         `yaml:"geo"`
	Analytics   AnalyticsConfig   `yaml:"analytics"`
}

type PersistenceConfig struct {
	Path string `yaml:"path"`
}

type AppLogsConfig struct {
	Path string `yaml:"path"`
}

type GeoConfig struct {
	Enabled         bool   `yaml:"enabled"`
	Provider        string `yaml:"provider"`
	TimeoutSeconds  int    `yaml:"timeout_seconds"`
	CacheTTLSeconds int    `yaml:"cache_ttl_seconds"`
}

type AnalyticsConfig struct {
	Path string `yaml:"path"`
}

type ServerConfig struct {
	Port     int    `yaml:"port"`
	Timezone string `yaml:"timezone"`
}

type NetworkConfig struct {
	Interfaces []string `yaml:"interfaces"`
	CIDRs      []string `yaml:"cidrs"`
	LeaseFile  string   `yaml:"lease_file"`
}

func (c *Config) ServerAddr() string {
	return fmt.Sprintf(":%d", c.Server.Port)
}

var defaults = Config{
	Server: ServerConfig{
		Port:     8086,
		Timezone: "Europe/Warsaw",
	},
	Network: NetworkConfig{
		Interfaces: []string{"wlan0"},
		LeaseFile:  "/var/lib/misc/dnsmasq.leases",
	},
	Persistence: PersistenceConfig{
		Path: "./data/lists.json",
	},
	AppLogs: AppLogsConfig{
		Path: "./data/app_logs.db",
	},
	Geo: GeoConfig{
		Enabled:         false,
		Provider:        "ip-api",
		TimeoutSeconds:  2,
		CacheTTLSeconds: 86400,
	},
	Analytics: AnalyticsConfig{
		Path: "./data/analytics.db",
	},
}

func Load(path string) (*Config, error) {
	cfg := defaults
	baseDir, err := configBaseDir(path)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			resolvePaths(&cfg, baseDir)
			return &cfg, nil
		}
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	resolvePaths(&cfg, baseDir)
	return &cfg, nil
}

func configBaseDir(path string) (string, error) {
	if path == "" {
		path = "."
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve config path %s: %w", path, err)
	}
	return filepath.Dir(abs), nil
}

func resolvePaths(cfg *Config, baseDir string) {
	cfg.Persistence.Path = resolvePath(baseDir, cfg.Persistence.Path)
	cfg.AppLogs.Path = resolvePath(baseDir, cfg.AppLogs.Path)
	cfg.Analytics.Path = resolvePath(baseDir, cfg.Analytics.Path)
}

func resolvePath(baseDir, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
}
