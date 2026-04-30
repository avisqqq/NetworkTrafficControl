package persist

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

type Store struct {
	mu   sync.Mutex
	path string
}

type data struct {
	Blacklist []string `json:"blacklist"`
	Whitelist []string `json:"whitelist"`
	OnlyLocal []string `json:"onlylocal"`
}

func New(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	return &Store{path: path}, nil
}

func (s *Store) Load() (blacklist, whitelist, onlylocal []string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil, nil, nil, nil
	}
	if err != nil {
		return nil, nil, nil, err
	}

	var d data
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, nil, nil, err
	}
	return d.Blacklist, d.Whitelist, d.OnlyLocal, nil
}

func (s *Store) Save(blacklist, whitelist, onlylocal []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := json.MarshalIndent(data{Blacklist: blacklist, Whitelist: whitelist, OnlyLocal: onlylocal}, "", "  ")
	if err != nil {
		return err
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
