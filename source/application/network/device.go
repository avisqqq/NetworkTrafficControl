package network

type NetworkDevice struct {
	IP       string   `json:"ip"`
	Aliases  []string `json:"aliases,omitempty"`
	Version  uint8    `json:"version"`
	MAC      string   `json:"mac,omitempty"`
	Hostname string   `json:"hostname,omitempty"`
	State    string   `json:"state,omitempty"`
	Source   []string `json:"sources"`
}
