package packet_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"ntc/source/domain/packet"
	infraebpf "ntc/source/infrastructure/packet"
)

type mockMap struct {
	entries []packet.IPKey
	addErr  error
	delErr  error
}

func (m *mockMap) Add(e packet.IPKey) error {
	if m.addErr != nil {
		return m.addErr
	}
	m.entries = append(m.entries, e)
	return nil
}

func (m *mockMap) Delete(e packet.IPKey) error {
	if m.delErr != nil {
		return m.delErr
	}
	for i, entry := range m.entries {
		if entry == e {
			m.entries = append(m.entries[:i], m.entries[i+1:]...)
			return nil
		}
	}
	return nil
}

func (m *mockMap) Get() ([]packet.IPKey, error) {
	return m.entries, nil
}

func (m *mockMap) Close() error { return nil }

func (m *mockMap) has(e packet.IPKey) bool {
	for _, entry := range m.entries {
		if entry == e {
			return true
		}
	}
	return false
}

func ipv4(addr string) packet.IPKey {
	key, err := packet.IPKeyFromString(addr)
	if err != nil {
		panic(err)
	}
	return key
}

func ipv6(addr string) packet.IPKey {
	key, err := packet.IPKeyFromString(addr)
	if err != nil {
		panic(err)
	}
	return key
}

func TestIpFilter_AddToBlacklist_GoesToBlacklistOnly(t *testing.T) {
	t.Parallel()

	ol, wl, bl := &mockMap{}, &mockMap{}, &mockMap{}
	f := infraebpf.NewIpFilter(ol, wl, bl)

	require.NoError(t, f.AddToBlacklist(ipv4("192.168.1.1")))

	assert.True(t, bl.has(ipv4("192.168.1.1")), "should be in blacklist")
	assert.False(t, wl.has(ipv4("192.168.1.1")), "must not leak into whitelist")
}

func TestIpFilter_AddToBlacklist_PropagatesError(t *testing.T) {
	t.Parallel()

	bl := &mockMap{addErr: errors.New("map full")}
	f := infraebpf.NewIpFilter(&mockMap{}, &mockMap{}, bl)

	err := f.AddToBlacklist(ipv4("1.2.3.4"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "map full")
}

func TestIpFilter_AddToWhitelist_GoesToWhitelistOnly(t *testing.T) {
	t.Parallel()

	ol, wl, bl := &mockMap{}, &mockMap{}, &mockMap{}
	f := infraebpf.NewIpFilter(ol, wl, bl)

	require.NoError(t, f.AddToWhitelist(ipv4("10.0.0.1")))

	assert.True(t, wl.has(ipv4("10.0.0.1")), "should be in whitelist")
	assert.False(t, bl.has(ipv4("10.0.0.1")), "must not leak into blacklist")
}

func TestIpFilter_AddToWhitelist_IPv6(t *testing.T) {
	t.Parallel()

	ol, wl, bl := &mockMap{}, &mockMap{}, &mockMap{}
	f := infraebpf.NewIpFilter(ol, wl, bl)

	require.NoError(t, f.AddToWhitelist(ipv6("::1")))

	assert.True(t, wl.has(ipv6("::1")))
	assert.False(t, bl.has(ipv6("::1")))
}

func TestIpFilter_DeleteFromBlacklist_RemovesEntry(t *testing.T) {
	t.Parallel()

	e := ipv4("1.1.1.1")
	bl := &mockMap{entries: []packet.IPKey{e}}
	f := infraebpf.NewIpFilter(&mockMap{}, &mockMap{}, bl)

	require.NoError(t, f.DeleteFromBlacklist(e))

	assert.False(t, bl.has(e), "entry should be removed")
}

func TestIpFilter_DeleteFromBlacklist_PropagatesError(t *testing.T) {
	t.Parallel()

	bl := &mockMap{delErr: errors.New("map error")}
	f := infraebpf.NewIpFilter(&mockMap{}, &mockMap{}, bl)

	err := f.DeleteFromBlacklist(ipv4("1.1.1.1"))

	require.Error(t, err)
}

func TestIpFilter_DeleteFromWhitelist_RemovesEntry(t *testing.T) {
	t.Parallel()

	e := ipv4("8.8.8.8")
	wl := &mockMap{entries: []packet.IPKey{e}}
	f := infraebpf.NewIpFilter(&mockMap{}, wl, &mockMap{})

	require.NoError(t, f.DeleteFromWhitelist(e))

	assert.False(t, wl.has(e), "entry should be removed")
}

func TestIpFilter_GetBlacklist_ReturnsAllEntries(t *testing.T) {
	t.Parallel()

	entries := []packet.IPKey{ipv4("1.2.3.4"), ipv4("5.6.7.8")}
	bl := &mockMap{entries: entries}
	f := infraebpf.NewIpFilter(&mockMap{}, &mockMap{}, bl)

	got, err := f.GetBlacklist()

	require.NoError(t, err)
	assert.ElementsMatch(t, entries, got)
}

func TestIpFilter_GetWhitelist_ReturnsAllEntries(t *testing.T) {
	t.Parallel()

	entries := []packet.IPKey{ipv6("::1"), ipv4("10.0.0.1")}
	wl := &mockMap{entries: entries}
	f := infraebpf.NewIpFilter(&mockMap{}, wl, &mockMap{})

	got, err := f.GetWhitelist()

	require.NoError(t, err)
	assert.ElementsMatch(t, entries, got)
}

func TestIpFilter_GetBlacklist_EmptyByDefault(t *testing.T) {
	t.Parallel()

	f := infraebpf.NewIpFilter(&mockMap{}, &mockMap{}, &mockMap{})

	got, err := f.GetBlacklist()

	require.NoError(t, err)
	assert.Empty(t, got)
}
