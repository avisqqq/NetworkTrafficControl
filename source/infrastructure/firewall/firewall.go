//go:build linux

package firewall

import (
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

const (
	tableName        = "ntc"
	tableFamily      = nftables.TableFamilyINet
	forwardChainName = "forward"
)

type Firewall struct {
	conn         *nftables.Conn
	table        *nftables.Table
	forwardChain *nftables.Chain
}

func NewFirewall(options ...nftables.ConnOption) (*Firewall, error) {
	conn, err := nftables.New(options...)
	if err != nil {
		return nil, fmt.Errorf("NewFirewall: failed to open nftables connection: %w", err)
	}

	table := &nftables.Table{
		Name:   tableName,
		Family: tableFamily,
	}

	policy := nftables.ChainPolicyAccept

	forwardChain := &nftables.Chain{
		Name:     forwardChainName,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policy,
	}

	return &Firewall{
		conn:         conn,
		table:        table,
		forwardChain: forwardChain,
	}, nil
}

func (f *Firewall) Setup() error {
	f.conn.AddTable(f.table)
	f.conn.AddChain(f.forwardChain)
	f.conn.FlushChain(f.forwardChain)
	f.conn.AddRule(&nftables.Rule{
		Table: f.table,
		Chain: f.forwardChain,
		Exprs: []expr.Any{
			&expr.Counter{},
		},
	})

	if err := f.conn.Flush(); err != nil {
		return fmt.Errorf("Firewall.Setup: failed to apply ruleset: %w", err)
	}

	return nil
}

func (f *Firewall) TearDown() error {
	f.conn.DelTable(f.table)

	if err := f.conn.Flush(); err != nil {
		return fmt.Errorf("Firewall.TearDown: failed to remove table %s: %w", tableName, err)
	}

	return nil
}

func (f *Firewall) ForwardCounter() (packets, bytes uint64, err error) {
	rules, err := f.conn.GetRules(f.table, f.forwardChain)
	if err != nil {
		return 0, 0, fmt.Errorf("Firewall.ForwardCounter: failed to read rules of chain %s: %w", forwardChainName, err)
	}
	for _, rule := range rules {
		for _, e := range rule.Exprs {
			counter, ok := e.(*expr.Counter)
			if !ok {
				continue
			}
			packets += counter.Packets
			bytes += counter.Bytes
		}
	}
	return packets, bytes, nil
}
