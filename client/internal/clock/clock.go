package clock

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Clock struct {
	boot time.Time
	loc  *time.Location
}

func New(tz string) *Clock {
	loc := time.Local
	if tz != "" {
		if l, err := time.LoadLocation(tz); err == nil {
			loc = l
		}
	}

	boot := bootTime()

	return &Clock{
		boot: boot,
		loc:  loc,
	}
}

func (c *Clock) FromTs(ts uint64) time.Time {
	if ts >= uint64(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano()) {
		return time.Unix(0, int64(ts)).In(c.loc)
	}
	return c.boot.Add(time.Duration(ts)).In(c.loc)
}

// bootTime returns the system boot time derived from /proc/uptime.
// On systems where /proc/uptime is unavailable (e.g. macOS in mock mode),
// it falls back to the Unix epoch.
func bootTime() time.Time {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return time.Unix(0, 0)
	}

	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return time.Unix(0, 0)
	}

	uptimeSec, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return time.Unix(0, 0)
	}

	return time.Now().Add(-time.Duration(uptimeSec * float64(time.Second)))
}
