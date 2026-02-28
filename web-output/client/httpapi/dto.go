package httpapi

type BlacklistReq struct {
	IP string `json:"ip"`
}
type BlacklistResp struct {
	OK bool   `json:"ok"`
	IP string `json:"ip"`
}
type WhitelistReq struct {
	IP string `json:"ip"`
}
type WhitelistResp struct {
	OK bool   `json:"ok"`
	IP string `json:"ip"`
}
