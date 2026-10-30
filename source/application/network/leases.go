package network

import (
	"bufio"
	"errors"
	"net"
	"ntc/source/domain/packet"
	"os"
	"os/exec"
	"strings"
)

func ReadDNSMasqLeases(path string) ([]NetworkDevice, error) {
	file, err := os.Open(path)

	if err != nil {
		return nil, err
	}

	defer func() { _ = file.Close() }()

	var devices []NetworkDevice

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}

		mac := fields[1]
		ip := fields[2]
		hostname := fields[3]

		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			continue
		}

		if hostname == "*" {
			hostname = ""
		}

		devices = append(devices, NetworkDevice{
			IP:       ip,
			Version:  packet.IPVersion(parsedIP),
			MAC:      mac,
			Hostname: hostname,
			Source:   []string{"dhcp"},
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return devices, nil
}

func ReadNeighbors(iface string) ([]NetworkDevice, error) {
	out, err := exec.Command("ip", "neigh", "show", "dev", iface).Output()
	if err != nil {
		return nil, err
	}

	var devices []NetworkDevice

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		ip := fields[0]
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			continue
		}

		device := NetworkDevice{
			IP:      ip,
			Version: packet.IPVersion(parsedIP),
			Source:  []string{"neigh"},
		}
		for i := 1; i < len(fields); i++ {
			switch fields[i] {
			case "lladdr":
				if i+1 < len(fields) {
					device.MAC = fields[i+1]
					i++
				}
			default:
				if isNeighborState(fields[i]) {
					device.State = fields[i]
				}
			}
		}
		devices = append(devices, device)
	}
	return devices, nil

}

func ReadSelfDevices() ([]NetworkDevice, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	hostname, _ := os.Hostname()
	self := NetworkDevice{
		Hostname: hostname,
		State:    "SELF",
		Source:   []string{"self"},
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP == nil {
				continue
			}
			ip := ipNet.IP
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
				continue
			}
			version := packet.IPVersion(ip)
			if self.IP == "" {
				self.IP = ip.String()
				self.Version = version
			} else if self.Version != 4 && version == 4 {
				self.Aliases = append(self.Aliases, self.IP)
				self.IP = ip.String()
				self.Version = version
			} else {
				self.Aliases = append(self.Aliases, ip.String())
			}
			if self.MAC == "" {
				self.MAC = iface.HardwareAddr.String()
			}
		}
	}
	if self.IP == "" {
		return nil, nil
	}
	return []NetworkDevice{self}, nil
}

func isNeighborState(s string) bool {
	switch s {
	case "INCOMPLETE", "REACHABLE", "STALE", "DELAY", "PROBE",
		"FAILED", "NOARP", "PERMANENT":
		return true
	default:
		return false
	}
}

func ReadDevices(iface, path string) ([]NetworkDevice, error) {
	leases, leasesErr := ReadDNSMasqLeases(path)
	neighbors, neighErr := ReadNeighbors(iface)
	selfDevices, selfErr := ReadSelfDevices()

	if leasesErr != nil && neighErr != nil && selfErr != nil {
		if errors.Is(leasesErr, os.ErrNotExist) {
			return []NetworkDevice{}, nil
		}
		return nil, leasesErr
	}

	merged := make(map[string]NetworkDevice)
	byIP := make(map[string]string)
	byMAC := make(map[string]string)

	for _, d := range leases {
		key := deviceKey(d)
		merged[key] = d
		indexDevice(byIP, byMAC, key, d)
	}
	for _, d := range selfDevices {
		key := knownDeviceKey(byIP, byMAC, d)
		if key == "" {
			key = deviceKey(d)
		}

		existing, ok := merged[key]
		if !ok {
			merged[key] = d
			indexDevice(byIP, byMAC, key, d)
			continue
		}

		merged[key] = mergeDevice(existing, d)
		indexDevice(byIP, byMAC, key, merged[key])
	}
	for _, d := range neighbors {
		key := knownDeviceKey(byIP, byMAC, d)
		if key == "" {
			key = deviceKey(d)
		}

		existing, ok := merged[key]
		if !ok {
			merged[key] = d
			indexDevice(byIP, byMAC, key, d)
			continue
		}

		merged[key] = mergeDevice(existing, d)
		indexDevice(byIP, byMAC, key, merged[key])
	}

	devices := make([]NetworkDevice, 0, len(merged))
	for _, d := range merged {
		devices = append(devices, d)
	}

	return devices, nil
}

func knownDeviceKey(byIP, byMAC map[string]string, d NetworkDevice) string {
	if d.MAC != "" {
		if key, ok := byMAC[strings.ToLower(d.MAC)]; ok {
			return key
		}
	}
	if d.IP != "" {
		if key, ok := byIP[d.IP]; ok {
			return key
		}
	}
	return ""
}

func indexDevice(byIP, byMAC map[string]string, key string, d NetworkDevice) {
	if d.IP != "" {
		byIP[d.IP] = key
	}
	if d.MAC != "" {
		byMAC[strings.ToLower(d.MAC)] = key
	}
}

func deviceKey(d NetworkDevice) string {
	if d.MAC != "" {
		return "mac:" + d.MAC
	}
	return "ip:" + d.IP
}

func mergeDevice(a, b NetworkDevice) NetworkDevice {
	if a.IP == "" {
		a.IP = b.IP
	}
	a.Aliases = mergedSources(a.Aliases, b.Aliases)
	if a.Version == 0 {
		a.Version = b.Version
	}
	if a.MAC == "" {
		a.MAC = b.MAC
	}
	if a.Hostname == "" {
		a.Hostname = b.Hostname
	}
	if a.State == "" {
		a.State = b.State
	}
	if b.State == "SELF" {
		a.State = b.State
	}

	a.Source = mergedSources(a.Source, b.Source)
	return a
}

func mergedSources(a, b []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, s := range a {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}

	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
