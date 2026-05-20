package network

import (
	"fmt"
	"net"
)

func LocalCIDRs(configCIDRs []string, ifaceName string) ([]string, error) {
	cidrs, hasV4, hasV6, err := parseConfiguredCIDRs(configCIDRs)
	if err != nil {
		return nil, err
	}
	discovered, discoveredHasV4, discoveredHasV6, err := discoverInterfaceCIDRs(ifaceName)
	if err != nil {
		if len(cidrs) > 0 {
			return cidrs, nil
		}
		return nil, err
	}

	if !hasV4 && discoveredHasV4 {
		cidrs = appendFamily(cidrs, discovered, 4)
	}
	if !hasV6 && discoveredHasV6 {
		cidrs = appendFamily(cidrs, discovered, 6)
	}

	if len(cidrs) == 0 {
		return nil, fmt.Errorf("no local CIDRs configured or discovered on %s", ifaceName)
	}
	return cidrs, nil
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

func appendFamily(dst, src []string, family uint8) []string {
	for _, raw := range src {
		ip, _, err := net.ParseCIDR(raw)
		if err != nil {
			continue
		}

		if family == 4 && ip.To4() != nil {
			dst = append(dst, raw)
		}
		if family == 6 && ip.To4() == nil {
			dst = append(dst, raw)
		}
	}
	return dst
}

func normalizeCIDR(ipNet *net.IPNet) string {
	return (&net.IPNet{
		IP:   ipNet.IP.Mask(ipNet.Mask),
		Mask: ipNet.Mask,
	}).String()
}
