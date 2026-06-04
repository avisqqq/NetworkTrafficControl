package geo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"ntc/source/application/inspection"
)

type IPAPIProvider struct {
	client   *http.Client
	cacheTTL time.Duration
	mu       sync.Mutex
	cache    map[string]cacheEntry
}

type cacheEntry struct {
	expires time.Time
	info    inspection.GeoInfo
}

type ipapiResponse struct {
	Status        string  `json:"status"`
	Message       string  `json:"message"`
	Query         string  `json:"query"`
	Continent     string  `json:"continent"`
	ContinentCode string  `json:"continentCode"`
	Country       string  `json:"country"`
	CountryCode   string  `json:"countryCode"`
	Region        string  `json:"region"`
	RegionName    string  `json:"regionName"`
	City          string  `json:"city"`
	District      string  `json:"district"`
	Zip           string  `json:"zip"`
	Lat           float64 `json:"lat"`
	Lon           float64 `json:"lon"`
	Timezone      string  `json:"timezone"`
	Offset        int     `json:"offset"`
	Currency      string  `json:"currency"`
	ISP           string  `json:"isp"`
	Org           string  `json:"org"`
	AS            string  `json:"as"`
	ASName        string  `json:"asname"`
	Mobile        bool    `json:"mobile"`
	Proxy         bool    `json:"proxy"`
	Hosting       bool    `json:"hosting"`
}

func NewIPAPIProvider(timeout, cacheTTL time.Duration) *IPAPIProvider {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if cacheTTL <= 0 {
		cacheTTL = 24 * time.Hour
	}

	return &IPAPIProvider{
		client:   &http.Client{Timeout: timeout},
		cacheTTL: cacheTTL,
		cache:    make(map[string]cacheEntry),
	}
}

func (p *IPAPIProvider) Lookup(ctx context.Context, ip string) (inspection.GeoInfo, error) {
	if info, ok := p.fromCache(ip); ok {
		return info, nil
	}

	endpoint := "http://ip-api.com/json/" + url.PathEscape(ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return inspection.GeoInfo{}, err
	}

	q := req.URL.Query()
	q.Set("fields", "status,message,query,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,mobile,proxy,hosting")
	req.URL.RawQuery = q.Encode()

	res, err := p.client.Do(req)
	if err != nil {
		return inspection.GeoInfo{}, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return inspection.GeoInfo{}, fmt.Errorf("geo provider returned %s", res.Status)
	}

	var api ipapiResponse
	if err := json.NewDecoder(res.Body).Decode(&api); err != nil {
		return inspection.GeoInfo{}, err
	}

	info := inspection.GeoInfo{
		Enabled:       true,
		Provider:      "ip-api",
		Status:        api.Status,
		Message:       api.Message,
		Query:         api.Query,
		Continent:     api.Continent,
		ContinentCode: api.ContinentCode,
		Country:       api.Country,
		CountryCode:   api.CountryCode,
		Region:        api.Region,
		RegionName:    api.RegionName,
		City:          api.City,
		District:      api.District,
		Zip:           api.Zip,
		Latitude:      api.Lat,
		Longitude:     api.Lon,
		Timezone:      api.Timezone,
		UTCOffset:     api.Offset,
		Currency:      api.Currency,
		ISP:           api.ISP,
		Organization:  api.Org,
		AS:            api.AS,
		ASName:        api.ASName,
		Mobile:        api.Mobile,
		Proxy:         api.Proxy,
		Hosting:       api.Hosting,
	}
	if info.Status != "success" {
		if info.Message == "" {
			info.Message = "lookup failed"
		}
		return info, errors.New(info.Message)
	}

	p.saveCache(ip, info)
	return info, nil
}

func (p *IPAPIProvider) fromCache(ip string) (inspection.GeoInfo, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	entry, ok := p.cache[ip]
	if !ok || time.Now().After(entry.expires) {
		if ok {
			delete(p.cache, ip)
		}
		return inspection.GeoInfo{}, false
	}
	return entry.info, true
}

func (p *IPAPIProvider) saveCache(ip string, info inspection.GeoInfo) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.cache[ip] = cacheEntry{
		expires: time.Now().Add(p.cacheTTL),
		info:    info,
	}
}
