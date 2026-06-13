package handlers

import (
	"encoding/json"
	"net/http"

	"ntc/source/application/analytics"
	"ntc/source/application/network"
)

type KnownHostRecorder interface {
	RecordKnownHosts(hosts []analytics.KnownHost) error
}

func HostnameHandler(iface, leaseFile string, mockMode bool, recorder KnownHostRecorder) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if mockMode {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(network.MockDevices())
			return
		}

		devices, err := network.ReadDevices(iface, leaseFile)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if recorder != nil {
			_ = recorder.RecordKnownHosts(knownHostsFromDevices(devices))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(devices)
	}
}

func knownHostsFromDevices(devices []network.NetworkDevice) []analytics.KnownHost {
	hosts := make([]analytics.KnownHost, 0, len(devices))
	for _, device := range devices {
		ips := append([]string{device.IP}, device.Aliases...)
		for _, ip := range ips {
			if ip == "" {
				continue
			}
			hosts = append(hosts, analytics.KnownHost{
				IP:       ip,
				Hostname: device.Hostname,
				MAC:      device.MAC,
			})
		}
	}
	return hosts
}
