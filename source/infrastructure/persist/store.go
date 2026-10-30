package persist

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"ntc/source/application/lists"
)

type Store struct {
	mu   sync.Mutex
	path string
}

type Data struct {
	Blacklist   []string `json:"blacklist"`
	Whitelist   []string `json:"whitelist"`
	OnlyLocal   []string `json:"onlylocal"`
	LocalNetsV4 []string `json:"local_nets_v4"`
	LocalNetsV6 []string `json:"local_nets_v6"`
	MockMode    bool     `json:"mock_mode"`
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
	return s.load()
}

func (s *Store) load() (Data, error) {
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

func (s *Store) LoadLists() (lists.ListSnapshot, error) {
	d, err := s.Load()
	if err != nil {
		return lists.ListSnapshot{}, err
	}
	return lists.ListSnapshot{
		Blacklist:   d.Blacklist,
		Whitelist:   d.Whitelist,
		OnlyLocal:   d.OnlyLocal,
		LocalNetsV4: d.LocalNetsV4,
		LocalNetsV6: d.LocalNetsV6,
	}, nil
}

func (s *Store) SaveLists(snapshot lists.ListSnapshot) error {
	return s.update(func(d *Data) {
		d.Blacklist = snapshot.Blacklist
		d.Whitelist = snapshot.Whitelist
		d.OnlyLocal = snapshot.OnlyLocal
		d.LocalNetsV4 = snapshot.LocalNetsV4
		d.LocalNetsV6 = snapshot.LocalNetsV6
	})
}

func (s *Store) SaveMockMode(mockMode bool) error {
	return s.update(func(d *Data) { d.MockMode = mockMode })
}

func (s *Store) Save(d Data) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.save(d)
}

func (s *Store) save(d Data) error {
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

func (s *Store) update(change func(*Data)) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	d, err := s.load()
	if err != nil {
		return err
	}
	change(&d)
	return s.save(d)
}
