package openconnect

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDataPacketQueueSignalsNotFullOnlyOnFullTransition(t *testing.T) {
	queue := newDataPacketQueue[int](2)
	if pushed := queue.PushBatch(context.Background(), []int{1}); pushed != 1 {
		t.Fatalf("push into empty queue: got %d, want 1", pushed)
	}
	notFull := queue.notFull
	if items := queue.Pop(1); len(items) != 1 || items[0] != 1 {
		t.Fatalf("pop from non-full queue: got %v, want [1]", items)
	}
	select {
	case <-notFull:
		t.Fatal("pop from a non-full queue signaled not-full")
	default:
	}
	if queue.notFull != notFull {
		t.Fatal("pop from a non-full queue replaced not-full notification")
	}

	if pushed := queue.PushBatch(context.Background(), []int{2, 3}); pushed != 2 {
		t.Fatalf("fill queue: got %d, want 2", pushed)
	}
	notFull = queue.notFull
	if items := queue.Pop(1); len(items) != 1 || items[0] != 2 {
		t.Fatalf("pop from full queue: got %v, want [2]", items)
	}
	select {
	case <-notFull:
	default:
		t.Fatal("pop from a full queue did not signal not-full")
	}
	if queue.notFull == notFull {
		t.Fatal("pop from a full queue did not replace not-full notification")
	}
}

func TestDataPacketQueueWakeAndClose(t *testing.T) {
	queue := newDataPacketQueue[int](2)
	select {
	case <-queue.Wake():
		t.Fatal("empty queue reported ready")
	default:
	}
	if pushed := queue.PushBatch(context.Background(), []int{1, 2}); pushed != 2 {
		t.Fatalf("fill queue: got %d, want 2", pushed)
	}
	for expected := 1; expected <= 2; expected++ {
		select {
		case <-queue.Wake():
		default:
			t.Fatalf("queue did not wake for item %d", expected)
		}
		items := queue.Pop(1)
		if len(items) != 1 || items[0] != expected {
			t.Fatalf("pop item %d: got %v", expected, items)
		}
	}
	select {
	case <-queue.Wake():
		t.Fatal("drained queue retained a stale wakeup")
	default:
	}
	wake := queue.Wake()
	queue.Close()
	select {
	case <-wake:
	default:
		t.Fatal("closed queue did not wake waiters")
	}
}

func TestDataPacketQueueConcurrentWakeups(t *testing.T) {
	const (
		producerCount  = 2
		consumerCount  = 2
		itemsPerSender = 256
		totalItems     = producerCount * itemsPerSender
	)
	queue := newDataPacketQueue[int](7)
	var seen [totalItems]atomic.Uint32
	var remaining atomic.Int64
	remaining.Store(totalItems)
	allRead := make(chan struct{})
	var allReadOnce sync.Once
	var consumers sync.WaitGroup
	consumers.Add(consumerCount)
	for range consumerCount {
		go func() {
			defer consumers.Done()
			for {
				items := queue.Pop(1)
				if len(items) == 0 {
					if queue.Closed() {
						return
					}
					<-queue.Wake()
					continue
				}
				item := items[0]
				if item < 0 || item >= totalItems || seen[item].Add(1) != 1 {
					t.Errorf("invalid or duplicate queue item: %d", item)
					continue
				}
				if remaining.Add(-1) == 0 {
					allReadOnce.Do(func() { close(allRead) })
				}
			}
		}()
	}
	var producers sync.WaitGroup
	producers.Add(producerCount)
	for producer := range producerCount {
		go func() {
			defer producers.Done()
			base := producer * itemsPerSender
			for index := range itemsPerSender {
				if queue.PushBatch(context.Background(), []int{base + index}) != 1 {
					t.Errorf("push item %d failed", base+index)
					return
				}
			}
		}()
	}
	producers.Wait()
	select {
	case <-allRead:
	case <-time.After(2 * time.Second):
		t.Fatalf("queue stalled with %d items unread", remaining.Load())
	}
	queue.Close()
	consumers.Wait()
}
