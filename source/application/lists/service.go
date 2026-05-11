package lists

import (
	"ntc/source/domain/packet/core"
)

type ListService struct {
	filter core.IpFilter
}

func NewListService(f core.IpFilter) *ListService {
	return &ListService{filter: f}
}
