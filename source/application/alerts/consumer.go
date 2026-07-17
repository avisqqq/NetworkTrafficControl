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

	mu       sync.Mutex
	lastSeen map[string]time.Time
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
		if !c.souldEmit(match.DeduplicationKey, now) {
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

func (c *Consumer) souldEmit(key string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	last, exists := c.lastSeen[key]
	if exists && now.Sub(last) < c.cooldown {
		return false
	}

	c.lastSeen[key] = now
	return true
}
