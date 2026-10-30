package analytics

import "testing"

func TestCloseFlushesBufferedStats(t *testing.T) {
	repo := &analyticsRepoStub{}
	service := NewService(repo, nil)
	service.pending["a"] = packetStat("192.168.1.10", "1.1.1.1", 10)

	service.Close()

	if len(repo.recordPacketsCalls) != 1 {
		t.Fatalf("expected one RecordPackets call, got %d", len(repo.recordPacketsCalls))
	}
	if len(repo.recordPacketsCalls[0]) != 1 {
		t.Fatalf("expected one stat in batch, got %d", len(repo.recordPacketsCalls[0]))
	}
	if len(service.pending) != 0 {
		t.Fatalf("expected pending stats to be drained, got %d", len(service.pending))
	}
}

func TestCloseTwiceDoesNotWriteAgain(t *testing.T) {
	repo := &analyticsRepoStub{}
	service := NewService(repo, nil)
	service.pending["a"] = packetStat("192.168.1.10", "1.1.1.1", 10)

	service.Close()
	service.Close()

	if len(repo.recordPacketsCalls) != 1 {
		t.Fatalf("second Close must not write again, got %d calls", len(repo.recordPacketsCalls))
	}
}
