package alerts

import (
	"context"
	"log"
	"sync"
	"time"

	"ntc/source/domain/alert"
	"ntc/source/domain/packet"
)

type Consumer struct {
	rules    []Rule
	sink     Sink
	cooldown time.Duration
	now      func() time.Time

	mu        sync.Mutex
	lastSeen  map[string]time.Time
	lastPrune time.Time
}

func NewConsumer(
	rules []Rule,
	sink Sink,
	cooldown time.Duration,
) *Consumer {
	return &Consumer{
		rules:    rules,
		sink:     sink,
		cooldown: cooldown,
		now:      time.Now,
		lastSeen: make(map[string]time.Time),
	}
}

func (c *Consumer) Consume(p packet.Packet) {
	for _, rule := range c.rules {
		match, matched := rule.Evaluate(p)
		if !matched {
			continue
		}

		now := c.now()
		if !c.shouldEmit(match.DeduplicationKey, now) {
			continue
		}

		candidate := alert.Alert{
			RuleID:           rule.ID(),
			RuleType:         rule.Type(),
			Severity:         rule.Severity(),
			Message:          match.Message,
			DeduplicationKey: match.DeduplicationKey,
			TriggeredAt:      now,
			Packet:           p,
			MatchedValue:     match.Value,
		}

		if err := c.sink.CreateAlert(context.Background(), candidate); err != nil {
			log.Printf("alerts: create alert %v", err)
		}
	}
}

func (c *Consumer) shouldEmit(key string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.prune(now)

	last, exists := c.lastSeen[key]
	if exists && now.Sub(last) < c.cooldown {
		return false
	}

	c.lastSeen[key] = now
	return true
}

// prune removes keys past their cooldown, because those keys no longer
// suppress anything. It sweeps at most once per cooldown to keep the packet
// path cheap, and it stops spoofed sources from growing lastSeen without limit.
func (c *Consumer) prune(now time.Time) {
	if now.Sub(c.lastPrune) < c.cooldown {
		return
	}
	c.lastPrune = now

	for key, last := range c.lastSeen {
		if now.Sub(last) >= c.cooldown {
			delete(c.lastSeen, key)
		}
	}
}
