package policy

import (
	"testing"

	"github.com/stretchr/testify/require"

	"ntc/source/domain/packet"
)

func TestRuleToString(t *testing.T) {
	ip, err := packet.IPKeyFromString("192.168.1.10")
	require.NoError(t, err)

	rule, err := NewRule(ip, 443, ProtocolTCP, packet.DirEgress)
	require.NoError(t, err)

	require.Equal(t, "192.168.1.10:443/TCP->EGRESS", rule.ToString())
}

func TestNewRuleRejectsInvalidValues(t *testing.T) {
	ip, err := packet.IPKeyFromString("192.168.1.10")
	require.NoError(t, err)

	tests := []struct {
		name      string
		port      uint16
		protocol  Protocol
		direction packet.Direction
	}{
		{"zero port", 0, ProtocolTCP, packet.DirIngress},
		{"unsupported protocol", 443, Protocol(1), packet.DirIngress},
		{"unsupported direction", 443, ProtocolTCP, packet.Direction(2)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewRule(ip, tt.port, tt.protocol, tt.direction)
			require.Error(t, err)
		})
	}
}
