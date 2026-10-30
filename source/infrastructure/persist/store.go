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

type Data struct {
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

func (s *Store) Load() (Data, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return Data{}, nil
	}
	if err != nil {
		return Data{}, err
	}

	var d Data
	if err := json.Unmarshal(b, &d); err != nil {
		return Data{}, err
	}
	return d, nil
}

func (s *Store) LoadLists() (blacklist, whitelist []string, err error) {
	d, err := s.Load()
	if err != nil {
		return nil, nil, err
	}
	return d.Blacklist, d.Whitelist, nil
}

func (s *Store) SaveLists(blacklist, whitelist []string) error {
	d, err := s.Load()
	if err != nil {
		return err
	}
	d.Blacklist = blacklist
	d.Whitelist = whitelist
	return s.Save(d)
}

func (s *Store) SaveMockMode(mockMode bool) error {
	d, err := s.Load()
	if err != nil {
		return err
	}
	d.MockMode = mockMode
	return s.Save(d)
}

func (s *Store) Save(d Data) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
