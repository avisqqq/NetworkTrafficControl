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

	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		panic(err)
	}

	fields := strings.Fields(string(data))
	uptimeSec, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		panic(err)
	}

	boot := time.Now().Add(-time.Duration(uptimeSec * float64(time.Second)))

	return &Clock{
		boot: boot,
		loc:  loc,
	}
}

func (c *Clock) FromTs(ts uint64) time.Time {
	return c.boot.Add(time.Duration(ts)).In(c.loc) // remove In if want UTC
}
