package alerts

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestShouldEmitSuppressesKeyDuringCooldown(t *testing.T) {
	consumer := NewConsumer(nil, nil, time.Second)
	start := time.Unix(1000, 0)

	require.True(t, consumer.shouldEmit("a", start))
	require.False(t, consumer.shouldEmit("a", start.Add(500*time.Millisecond)))
	require.True(t, consumer.shouldEmit("a", start.Add(time.Second)))
}

func TestShouldEmitPrunesExpiredKeys(t *testing.T) {
	consumer := NewConsumer(nil, nil, time.Second)
	start := time.Unix(1000, 0)

	require.True(t, consumer.shouldEmit("a", start))
	require.True(t, consumer.shouldEmit("b", start))
	require.True(t, consumer.shouldEmit("c", start.Add(2*time.Second)))

	require.Equal(t, []string{"c"}, keys(consumer.lastSeen))
}

func keys(seen map[string]time.Time) []string {
	result := make([]string, 0, len(seen))
	for key := range seen {
		result = append(result, key)
	}
	return result
}
