package network

import (
	"fmt"
	"net"
)

func LocalCIDRs(configCIDRs []string, ifaceName string) ([]string, error) {
	if len(configCIDRs) > 0 {
		cidrs, _, _, err := parseConfiguredCIDRs(configCIDRs)
		if err != nil {
			return nil, err
		}
		return cidrs, nil
	}

	discovered, _, _, err := discoverInterfaceCIDRs(ifaceName)
	if err != nil {
		return nil, err
	}
	if len(discovered) == 0 {
		return nil, fmt.Errorf("no local CIDRs configured or discovered on %s", ifaceName)
	}
	return discovered, nil
}

func parseConfiguredCIDRs(rawCIDRs []string) ([]string, bool, bool, error) {
	cidrs := make([]string, 0, len(rawCIDRs))
	hasV4 := false
	hasV6 := false

	for _, raw := range rawCIDRs {
		ip, ipNet, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, false, false, fmt.Errorf("invalid local CIDR %q: %w", raw, err)
		}

		cidrs = append(cidrs, normalizeCIDR(ipNet))

		if ip.To4() != nil {
			hasV4 = true
		} else {
			hasV6 = true
		}
	}
	return cidrs, hasV4, hasV6, nil

}

func discoverInterfaceCIDRs(ifaceName string) ([]string, bool, bool, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, false, false, fmt.Errorf("get interface %s: %w", ifaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, false, false, fmt.Errorf("get interface %s address: %w", ifaceName, err)
	}

	var cidrs []string
	hasV4 := false
	hasV6 := false

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP == nil {
			continue
		}

		ip := ipNet.IP
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			continue
		}

		cidrs = append(cidrs, normalizeCIDR(ipNet))

		if ip.To4() != nil {
			hasV4 = true
		} else {
			hasV6 = true
		}
	}
	return cidrs, hasV4, hasV6, nil
}

func normalizeCIDR(ipNet *net.IPNet) string {
	return (&net.IPNet{
		IP:   ipNet.IP.Mask(ipNet.Mask),
		Mask: ipNet.Mask,
	}).String()
}
