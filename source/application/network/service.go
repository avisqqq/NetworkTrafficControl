package network

import (
	"fmt"

	domainNetwork "ntc/source/domain/network"
	networkCore "ntc/source/domain/network/core"
)

type Service struct {
	cidrFilter networkCore.CIDRFilter
}

func NewService(cidrFilter networkCore.CIDRFilter) *Service {
	return &Service{cidrFilter: cidrFilter}
}

func (s *Service) LoadDefaultLocalNets(configCIDRs []string, iface string) ([]domainNetwork.CIDR, error) {
	rawCIDRs, err := LocalCIDRs(configCIDRs, iface)
	if err != nil {
		return nil, err
	}

	loaded := make([]domainNetwork.CIDR, 0, len(rawCIDRs))
	for _, raw := range rawCIDRs {
		cidr, err := domainNetwork.CIDRFromString(raw)
		if err != nil {
			return nil, fmt.Errorf("parse local CIDR %q: %w", raw, err)
		}

		switch cidr.Version {
		case 4:
			if err := s.cidrFilter.AddLocalCIDRV4(cidr); err != nil {
				return nil, fmt.Errorf("load local IPv4 CIDR %s: %w", cidr.ToString(), err)
			}
		case 6:
			if err := s.cidrFilter.AddLocalCIDRV6(cidr); err != nil {
				return nil, fmt.Errorf("load local IPv6 CIDR %s: %w", cidr.ToString(), err)
			}
		default:
			return nil, fmt.Errorf("unsupported CIDR IP version %d for %s", cidr.Version, raw)
		}

		loaded = append(loaded, cidr)
	}

	return loaded, nil
}
