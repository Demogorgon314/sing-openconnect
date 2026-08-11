package openconnect

import (
	"context"
	"testing"
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
