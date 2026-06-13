package core 

import "ntc/source/domain/network"

type CIDRFilter interface {
      AddLocalCIDRV4(network.CIDR) error
      DeleteLocalCIDRV4(network.CIDR) error
      GetLocalCIDRsV4() ([]network.CIDR, error)
      AddLocalCIDRV6(network.CIDR) error
      DeleteLocalCIDRV6(network.CIDR) error
      GetLocalCIDRsV6() ([]network.CIDR, error)
}