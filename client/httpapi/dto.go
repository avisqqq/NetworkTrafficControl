package httpapi

import (
	"time"

	"client/internal/model"
)

type IpRequest struct {
	IP string `json:"ip"`
}
type IpResponse struct {
	OK      bool   `json:"ok"`
	IP      string `json:"ip"`
	Version uint8  `json:"version"`
}

type EventDTO struct {
	Time      string `json:"time"`
	Seq       uint64 `json:"seq"`
	Interface string `json:"iface"`
	Ifindex   uint32 `json:"ifindex"`
	Direction string `json:"direction"`
	Src       string `json:"src"`
	Dst       string `json:"dst"`
	SrcPort   uint16 `json:"src_port"`
	DstPort   uint16 `json:"dst_port"`
	Proto     string `json:"proto"`
	Action    string `json:"action"`
}

func NewEventDTO(e model.Event, ifaceName string, eventTime time.Time) EventDTO {
	return EventDTO{
		Time:      eventTime.Format("15:04:05.000"),
		Seq:       e.Seq,
		Interface: ifaceName,
		Ifindex:   e.Ifindex,
		Direction: model.ParseDirection(e.Direction).String(),
		Src:       model.ParseRawIP(e.Src, e.IPVersion),
		Dst:       model.ParseRawIP(e.Dst, e.IPVersion),
		SrcPort:   e.SrcPort,
		DstPort:   e.DstPort,
		Proto:     model.ProtoString(e.Proto),
		Action:    model.ParseAction(e.Action).String(),
	}
}
