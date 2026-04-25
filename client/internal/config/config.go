package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server      ServerConfig      `yaml:"server"`
	Network     NetworkConfig     `yaml:"network"`
	Persistence PersistenceConfig `yaml:"persistence"`
}

type PersistenceConfig struct {
	Path string `yaml:"path"`
}

type ServerConfig struct {
	Port     int    `yaml:"port"`
	Timezone string `yaml:"timezone"`
}

type NetworkConfig struct {
	Interfaces []string `yaml:"interfaces"`
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
	},
	Persistence: PersistenceConfig{
		Path: "./data/lists.json",
	},
}

func Load(path string) (*Config, error) {
	cfg := defaults

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &cfg, nil
		}
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	return &cfg, nil
}
