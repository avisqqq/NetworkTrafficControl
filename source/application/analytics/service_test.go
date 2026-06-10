package analytics

import (
	"errors"
	"fmt"
	"io"
	"log"
	"testing"
	"time"
)

type analyticsRepoStub struct {
	recordPacketsCalls [][]PacketStat
	recordPacketsErr   error
}

func (r *analyticsRepoStub) RecordPacket(stat PacketStat) error {
	return r.RecordPackets([]PacketStat{stat})
}

func (r *analyticsRepoStub) RecordPackets(stats []PacketStat) error {
	copied := append([]PacketStat(nil), stats...)
	r.recordPacketsCalls = append(r.recordPacketsCalls, copied)
	return r.recordPacketsErr
}

func (r *analyticsRepoStub) Summary(limit int) (Summary, error) {
	return Summary{}, nil
}

func (r *analyticsRepoStub) HostSummary(ip string, limit int) (Summary, error) {
	return Summary{}, nil
}

func TestServiceFlushPersistsPendingStatsInOneBatch(t *testing.T) {
	repo := &analyticsRepoStub{}
	service := NewService(repo, nil)
	service.pending["a"] = packetStat("192.168.1.10", "1.1.1.1", 10)
	service.pending["b"] = packetStat("192.168.1.10", "8.8.8.8", 20)

	service.flush()

	if len(repo.recordPacketsCalls) != 1 {
		t.Fatalf("expected one RecordPackets call, got %d", len(repo.recordPacketsCalls))
	}
	if len(repo.recordPacketsCalls[0]) != 2 {
		t.Fatalf("expected two stats in batch, got %d", len(repo.recordPacketsCalls[0]))
	}
	if len(service.pending) != 0 {
		t.Fatalf("expected pending stats to be drained, got %d", len(service.pending))
	}
}

func TestServiceFlushPersistsManyPendingStatsInOneBatch(t *testing.T) {
	repo := &analyticsRepoStub{}
	service := NewService(repo, nil)

	for i := 0; i < 250; i++ {
		key := fmt.Sprintf("stat-%d", i)
		service.pending[key] = packetStat("192.168.1.10", fmt.Sprintf("203.0.113.%d", i), 1)
	}

	service.flush()

	if len(repo.recordPacketsCalls) != 1 {
		t.Fatalf("expected one RecordPackets call, got %d", len(repo.recordPacketsCalls))
	}
	if len(repo.recordPacketsCalls[0]) != 250 {
		t.Fatalf("expected 250 stats in batch, got %d", len(repo.recordPacketsCalls[0]))
	}
}

func TestServiceFlushRequeuesFailedBatch(t *testing.T) {
	discardLogs(t)
	repo := &analyticsRepoStub{recordPacketsErr: errors.New("temporary write failure")}
	service := NewService(repo, nil)
	service.pending["a"] = packetStat("192.168.1.10", "1.1.1.1", 10)

	service.flush()

	if len(repo.recordPacketsCalls) != 1 {
		t.Fatalf("expected one RecordPackets call, got %d", len(repo.recordPacketsCalls))
	}
	if len(service.pending) != 1 {
		t.Fatalf("expected failed batch to be requeued, got %d pending stats", len(service.pending))
	}
}

func TestServiceFlushRequeuesDatabaseLockedWithoutDisablingWrites(t *testing.T) {
	discardLogs(t)
	repo := &analyticsRepoStub{recordPacketsErr: errors.New("database is locked")}
	service := NewService(repo, nil)

	for i := 0; i < 3; i++ {
		service.pending["a"] = packetStat("192.168.1.10", "1.1.1.1", uint64(i+1))
		service.flush()
	}

	if service.writesDisabled {
		t.Fatal("expected database locked errors to leave analytics writes enabled")
	}
	if len(service.pending) != 1 {
		t.Fatalf("expected locked batch to be requeued, got %d pending stats", len(service.pending))
	}
}

func TestServiceFlushDisablesWritesAfterFatalSQLiteWriteFailure(t *testing.T) {
	for _, errMsg := range []string{"disk I/O error", "input/output error"} {
		t.Run(errMsg, func(t *testing.T) {
			discardLogs(t)
			repo := &analyticsRepoStub{recordPacketsErr: errors.New(errMsg)}
			service := NewService(repo, nil)
			service.pending["a"] = packetStat("192.168.1.10", "1.1.1.1", 1)

			service.flush()

			if !service.writesDisabled {
				t.Fatal("expected analytics writes to be disabled")
			}
			if len(service.pending) != 0 {
				t.Fatalf("expected pending stats to be cleared after disabling writes, got %d", len(service.pending))
			}
		})
	}
}

func TestServiceAddPendingDropsNewStatsAtPendingLimit(t *testing.T) {
	discardLogs(t)
	service := NewService(&analyticsRepoStub{}, nil)

	for i := 0; i < maxPendingStats+1; i++ {
		service.addPending(packetStat("192.168.1.10", fmt.Sprintf("203.0.113.%d", i), 1))
	}

	if len(service.pending) != maxPendingStats {
		t.Fatalf("expected pending stats to be capped at %d, got %d", maxPendingStats, len(service.pending))
	}

	service.writesDisabled = true
	service.addPending(packetStat("192.168.1.10", "8.8.8.8", 10))
	if len(service.pending) != maxPendingStats {
		t.Fatalf("expected addPending to ignore stats after writes are disabled, got %d", len(service.pending))
	}
}

func TestServiceAddPendingIgnoresStatsAfterWritesDisabled(t *testing.T) {
	service := NewService(&analyticsRepoStub{}, nil)
	service.writesDisabled = true

	service.addPending(packetStat("192.168.1.10", "8.8.8.8", 10))

	if len(service.pending) != 0 {
		t.Fatalf("expected addPending to ignore stats after writes are disabled, got %d", len(service.pending))
	}
}

func packetStat(hostIP, peerIP string, packets uint64) PacketStat {
	return PacketStat{
		HostIP:    hostIP,
		PeerIP:    peerIP,
		HostScope: "PRIVATE",
		PeerScope: "PUBLIC",
		Proto:     "TCP",
		Port:      443,
		Service:   "HTTPS",
		Direction: "EGRESS",
		Action:    "PASS",
		Packets:   packets,
		Bytes:     packets * 100,
		SeenAt:    time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC),
	}
}

func discardLogs(t *testing.T) {
	t.Helper()

	original := log.Writer()
	log.SetOutput(io.Discard)
	t.Cleanup(func() {
		log.SetOutput(original)
	})
}
