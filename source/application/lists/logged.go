package lists

import (
	"context"

	"ntc/source/domain/network"
	"ntc/source/domain/packet"
	"ntc/source/domain/policy"
)

type ActionLogger interface {
	ListActionSucceeded(ctx context.Context, list, action, value string)
	ListActionFailed(ctx context.Context, list, action, value string, err error)
}

type LoggedListManager struct {
	next   ListManager
	logger ActionLogger
}

func NewLoggedListManager(next ListManager, logger ActionLogger) *LoggedListManager {
	return &LoggedListManager{next: next, logger: logger}
}

func (m *LoggedListManager) AddToBlackListByString(ip string) (packet.IPKey, error) {
	key, err := m.next.AddToBlackListByString(ip)
	m.logIPResult("blacklist", "add", ip, key, err)
	return key, err
}

func (m *LoggedListManager) RemoveFromBlackListByString(ip string) (packet.IPKey, error) {
	key, err := m.next.RemoveFromBlackListByString(ip)
	m.logIPResult("blacklist", "remove", ip, key, err)
	return key, err
}

func (m *LoggedListManager) GetFromBlackListByString() ([]packet.IPEntry, error) {
	return m.next.GetFromBlackListByString()
}

func (m *LoggedListManager) AddToWhiteListByString(ip string) (packet.IPKey, error) {
	key, err := m.next.AddToWhiteListByString(ip)
	m.logIPResult("whitelist", "add", ip, key, err)
	return key, err
}

func (m *LoggedListManager) RemoveFromWhiteListByString(ip string) (packet.IPKey, error) {
	key, err := m.next.RemoveFromWhiteListByString(ip)
	m.logIPResult("whitelist", "remove", ip, key, err)
	return key, err
}

func (m *LoggedListManager) GetFromWhiteListByString() ([]packet.IPEntry, error) {
	return m.next.GetFromWhiteListByString()
}

func (m *LoggedListManager) AddToOnlyLocalByString(ip string) (packet.IPKey, error) {
	key, err := m.next.AddToOnlyLocalByString(ip)
	m.logIPResult("onlylocal", "add", ip, key, err)
	return key, err
}

func (m *LoggedListManager) RemoveFromOnlyLocalByString(ip string) (packet.IPKey, error) {
	key, err := m.next.RemoveFromOnlyLocalByString(ip)
	m.logIPResult("onlylocal", "remove", ip, key, err)
	return key, err
}

func (m *LoggedListManager) GetFromOnlyLocalByString() ([]packet.IPEntry, error) {
	return m.next.GetFromOnlyLocalByString()
}

func (m *LoggedListManager) AddToLocalNetsV4(cidr string) (network.CIDR, error) {
	key, err := m.next.AddToLocalNetsV4(cidr)
	m.logCIDRResult("localnet_v4", "add", cidr, key, err)
	return key, err
}

func (m *LoggedListManager) RemoveFromLocalNetsV4(cidr string) (network.CIDR, error) {
	key, err := m.next.RemoveFromLocalNetsV4(cidr)
	m.logCIDRResult("localnet_v4", "remove", cidr, key, err)
	return key, err
}

func (m *LoggedListManager) GetFromLocalNetsV4() ([]network.CIDREntry, error) {
	return m.next.GetFromLocalNetsV4()
}

func (m *LoggedListManager) AddToLocalNetsV6(cidr string) (network.CIDR, error) {
	key, err := m.next.AddToLocalNetsV6(cidr)
	m.logCIDRResult("localnet_v6", "add", cidr, key, err)
	return key, err
}

func (m *LoggedListManager) RemoveFromLocalNetsV6(cidr string) (network.CIDR, error) {
	key, err := m.next.RemoveFromLocalNetsV6(cidr)
	m.logCIDRResult("localnet_v6", "remove", cidr, key, err)
	return key, err
}

func (m *LoggedListManager) GetFromLocalNetsV6() ([]network.CIDREntry, error) {
	return m.next.GetFromLocalNetsV6()
}

func (m *LoggedListManager) logIPResult(list, action, raw string, key packet.IPKey, err error) {
	if err != nil {
		m.logger.ListActionFailed(context.Background(), list, action, raw, err)
		return
	}
	m.logger.ListActionSucceeded(context.Background(), list, action, key.ToString())
}

func (m *LoggedListManager) logCIDRResult(list, action, raw string, key network.CIDR, err error) {
	if err != nil {
		m.logger.ListActionFailed(context.Background(), list, action, raw, err)
		return
	}
	m.logger.ListActionSucceeded(context.Background(), list, action, key.ToString())
}

// Policy
func (m *LoggedListManager) AddPolicy(rule policy.Rule) error {
	err := m.next.AddPolicy(rule)
	m.logPolicy("policy", "add", rule, err)
	return err
}

func (m *LoggedListManager) RemovePolicy(rule policy.Rule) error {
	err := m.next.RemovePolicy(rule)
	m.logPolicy("policy", "remove", rule, err)
	return err
}

func (m *LoggedListManager) GetPolicy() ([]policy.Rule, error) {
	return m.next.GetPolicy()
}

func (m *LoggedListManager) logPolicy(list, action string, key policy.Rule, err error) {
	if err != nil {
		m.logger.ListActionFailed(context.Background(), list, action, key.ToString(), err)
		return
	}
	m.logger.ListActionSucceeded(context.Background(), list, action, key.ToString())
}
