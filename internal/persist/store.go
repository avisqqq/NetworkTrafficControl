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
	MockMode  bool     `json:"mock_mode"`
}

func New(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	return &Store{path: path}, nil
}

func (s *Store) Load() (blacklist, whitelist []string, err error) {
	blacklist, whitelist, _, err = s.LoadState()
	return blacklist, whitelist, err
}

func (s *Store) LoadState() (blacklist, whitelist []string, mockMode bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil, nil, false, nil
	}
	if err != nil {
		return nil, nil, false, err
	}

	var d data
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, nil, false, err
	}
	return d.Blacklist, d.Whitelist, d.MockMode, nil
}

func (s *Store) Save(blacklist, whitelist []string) error {
	_, _, mockMode, err := s.LoadState()
	if err != nil {
		return err
	}
	return s.SaveState(blacklist, whitelist, mockMode)
}

func (s *Store) SaveMockMode(mockMode bool) error {
	blacklist, whitelist, _, err := s.LoadState()
	if err != nil {
		return err
	}
	return s.SaveState(blacklist, whitelist, mockMode)
}

func (s *Store) SaveState(blacklist, whitelist []string, mockMode bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := json.MarshalIndent(data{Blacklist: blacklist, Whitelist: whitelist, MockMode: mockMode}, "", "  ")
	if err != nil {
		return err
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
