package system

type Snapshot struct {
	CPU       CPU       `json:"cpu"`
	RAM       RAM       `json:"ram"`
	Network   Network   `json:"network"`
	Processes []Process `json:"processes"`
}

type CPU struct {
	TotalPercent float64   `json:"totalPercent"`
	CoresPercent []float64 `json:"coresPercent"`
}

type RAM struct {
	UsedBytes   uint64  `json:"usedBytes"`
	TotalBytes  uint64  `json:"totalBytes"`
	UsedPercent float64 `json:"usedPercent"`
}

type Network struct {
	RxBytesPerSec uint64 `json:"rxBytesPerSec"`
	TxBytesPerSec uint64 `json:"txBytesPerSec"`
}

type Process struct {
	PID        int32   `json:"pid"`
	Name       string  `json:"name"`
	CPUPercent float64 `json:"cpuPercent"`
	RAMBytes   uint64  `json:"ramBytes"`
	RAMPercent float32 `json:"ramPercent"`
}
