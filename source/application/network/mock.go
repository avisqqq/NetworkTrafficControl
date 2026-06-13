package network

func MockDevices() []NetworkDevice {
	return []NetworkDevice{
		{
			IP:       "192.168.1.1",
			Version:  4,
			MAC:      "02:00:00:00:01:01",
			Hostname: "router.lan",
			State:    "REACHABLE",
			Source:   []string{"mock", "dhcp"},
		},
		{
			IP:       "192.168.1.100",
			Version:  4,
			MAC:      "02:00:00:00:01:64",
			Hostname: "workstation.office.lan",
			State:    "REACHABLE",
			Source:   []string{"mock", "dhcp", "neigh"},
		},
		{
			IP:       "192.168.1.200",
			Version:  4,
			MAC:      "02:00:00:00:01:c8",
			Hostname: "nas.media.lan",
			State:    "STALE",
			Source:   []string{"mock", "dhcp", "neigh"},
		},
		{
			IP:       "10.0.0.50",
			Version:  4,
			MAC:      "02:00:00:00:0a:32",
			Hostname: "camera.frontdoor.iot.lan",
			State:    "REACHABLE",
			Source:   []string{"mock", "dhcp"},
		},
		{
			IP:       "10.0.0.100",
			Version:  4,
			MAC:      "02:00:00:00:0a:64",
			Hostname: "printer.office.lan",
			State:    "DELAY",
			Source:   []string{"mock", "neigh"},
		},
		{
			IP:       "2606:4700:4700::1111",
			Version:  6,
			MAC:      "02:00:00:00:06:11",
			Hostname: "dns.cloudflare.test",
			State:    "REACHABLE",
			Source:   []string{"mock", "neigh"},
		},
	}
}
