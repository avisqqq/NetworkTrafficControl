package system

import (
	"sort"
	"sync"
	"time"

	domainsystem "ntc/source/domain/system"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/mem"
	gopsnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

type SystemCollector struct {
	mu      sync.Mutex
	prevRx  uint64
	prevTx  uint64
	prevAt  time.Time
	hasPrev bool
}

func NewSystemCollector() *SystemCollector {
	return &SystemCollector{}
}

func (c *SystemCollector) Snapshot() (domainsystem.Snapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	totalCPU, _ := cpu.Percent(0, false)
	coreCPU, _ := cpu.Percent(0, true)
	vm, err := mem.VirtualMemory()
	if err != nil {
		return domainsystem.Snapshot{}, err
	}

	rxRate, txRate := c.networkRates()
	processes := c.processes()

	var total float64
	if len(totalCPU) > 0 {
		total = totalCPU[0]
	}

	return domainsystem.Snapshot{
		CPU: domainsystem.CPU{
			TotalPercent: total,
			CoresPercent: coreCPU,
		},
		RAM: domainsystem.RAM{
			UsedBytes:   vm.Used,
			TotalBytes:  vm.Total,
			UsedPercent: vm.UsedPercent,
		},
		Network: domainsystem.Network{
			RxBytesPerSec: rxRate,
			TxBytesPerSec: txRate,
		},
		Processes: processes,
	}, nil
}

func (c *SystemCollector) networkRates() (uint64, uint64) {
	counters, err := gopsnet.IOCounters(false)
	if err != nil || len(counters) == 0 {
		return 0, 0
	}

	now := time.Now()
	currentRx := counters[0].BytesRecv
	currentTx := counters[0].BytesSent

	var rxRate uint64
	var txRate uint64
	if c.hasPrev {
		elapsed := now.Sub(c.prevAt).Seconds()
		if elapsed > 0 {
			if currentRx >= c.prevRx {
				rxRate = uint64(float64(currentRx-c.prevRx) / elapsed)
			}
			if currentTx >= c.prevTx {
				txRate = uint64(float64(currentTx-c.prevTx) / elapsed)
			}
		}
	}

	c.prevRx = currentRx
	c.prevTx = currentTx
	c.prevAt = now
	c.hasPrev = true

	return rxRate, txRate
}

func (c *SystemCollector) processes() []domainsystem.Process {
	procs, err := process.Processes()
	if err != nil {
		return nil
	}

	rows := make([]domainsystem.Process, 0, len(procs))
	for _, proc := range procs {
		name, err := proc.Name()
		if err != nil {
			continue
		}

		cpuPercent, _ := proc.CPUPercent()
		ramPercent, _ := proc.MemoryPercent()

		var rss uint64
		if memInfo, err := proc.MemoryInfo(); err == nil && memInfo != nil {
			rss = memInfo.RSS
		}

		rows = append(rows, domainsystem.Process{
			PID:        proc.Pid,
			Name:       name,
			CPUPercent: cpuPercent,
			RAMBytes:   rss,
			RAMPercent: ramPercent,
		})
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].CPUPercent == rows[j].CPUPercent {
			return rows[i].RAMBytes > rows[j].RAMBytes
		}
		return rows[i].CPUPercent > rows[j].CPUPercent
	})

	if len(rows) > 80 {
		return rows[:80]
	}

	return rows
}
