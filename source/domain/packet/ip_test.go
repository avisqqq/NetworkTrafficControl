package packet_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"ntc/source/domain/packet"
)

func TestIPKeyFromString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       string
		wantVersion uint8
		wantErr     bool
	}{
		{
			name:        "valid ipv4",
			input:       "192.168.1.1",
			wantVersion: 4,
		},
		{
			name:        "valid ipv4 - all zeros",
			input:       "0.0.0.0",
			wantVersion: 4,
		},
		{
			name:        "valid ipv4 - broadcast",
			input:       "255.255.255.255",
			wantVersion: 4,
		},
		{
			name:        "valid ipv6 - full",
			input:       "2001:db8::1",
			wantVersion: 6,
		},
		{
			name:        "valid ipv6 - loopback",
			input:       "::1",
			wantVersion: 6,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "invalid - random text",
			input:   "not-an-ip",
			wantErr: true,
		},
		{
			name:    "invalid - out of range octet",
			input:   "999.0.0.1",
			wantErr: true,
		},
		{
			name:    "invalid - partial ip",
			input:   "192.168",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			key, err := packet.IPKeyFromString(tt.input)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantVersion, key.Version)
		})
	}
}

func TestIPKey_ToString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{name: "ipv4 roundtrip", input: "192.168.1.1"},
		{name: "ipv4 zeros", input: "0.0.0.0"},
		{name: "ipv4 broadcast", input: "255.255.255.255"},
		{name: "ipv6 loopback", input: "::1"},
		{name: "ipv6 full", input: "2001:db8::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			key, err := packet.IPKeyFromString(tt.input)
			require.NoError(t, err)

			got := key.ToString()
			assert.NotEmpty(t, got)

			key2, err := packet.IPKeyFromString(got)
			require.NoError(t, err)
			assert.Equal(t, key, key2, "ToString output must parse back to the same key")
		})
	}
}

func TestIPKey_Version_IPv4_AddressBytes(t *testing.T) {
	t.Parallel()

	key, err := packet.IPKeyFromString("10.0.0.1")
	require.NoError(t, err)

	assert.Equal(t, uint8(4), key.Version)

	assert.Equal(t, byte(10), key.Address[0])
	assert.Equal(t, byte(0), key.Address[1])
	assert.Equal(t, byte(0), key.Address[2])
	assert.Equal(t, byte(1), key.Address[3])
	for i := 4; i < 16; i++ {
		assert.Equal(t, byte(0), key.Address[i], "byte %d should be zero for IPv4", i)
	}
}
