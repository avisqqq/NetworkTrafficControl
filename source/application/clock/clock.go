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
	return c.boot.Add(time.Duration(ts)).In(c.loc)
}

// bootTime returns the system boot time derived from /proc/uptime.
// On systems where /proc/uptime is unavailable (e.g. macOS in mock mode),
// it falls back to the Unix epoch so that Unix-nanosecond timestamps
// produced by the mock generator are interpreted correctly.
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
