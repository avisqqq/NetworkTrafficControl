package httpapi

type IpRequest struct {
	IP string `json:"ip"`
}

type IpResponse struct {
	OK      bool   `json:"ok"`
	IP      string `json:"ip"`
	Version uint8  `json:"version"`
}