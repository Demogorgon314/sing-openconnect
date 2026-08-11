package openconnect

import (
	"context"
	"sync"
)

type dataPacketQueue[T any] struct {
	access   sync.Mutex
	items    []T
	head     int
	length   int
	notEmpty chan struct{}
	notFull  chan struct{}
	closed   bool
}

func newDataPacketQueue[T any](capacity int) *dataPacketQueue[T] {
	return &dataPacketQueue[T]{
		items:    make([]T, capacity),
		notEmpty: make(chan struct{}, 1),
		notFull:  make(chan struct{}),
	}
}

func (q *dataPacketQueue[T]) PushBatch(ctx context.Context, items []T) int {
	pushed := 0
	for pushed < len(items) {
		q.access.Lock()
		if q.closed || ctx.Err() != nil {
			q.access.Unlock()
			return pushed
		}
		if q.length < len(q.items) {
			wasEmpty := q.length == 0
			tail := (q.head + q.length) % len(q.items)
			q.items[tail] = items[pushed]
			q.length++
			pushed++
			if wasEmpty {
				q.signalNotEmptyLocked()
			}
			q.access.Unlock()
			continue
		}
		notFull := q.notFull
		q.access.Unlock()
		select {
		case <-ctx.Done():
			return pushed
		case <-notFull:
		}
	}
	return pushed
}

func (q *dataPacketQueue[T]) TryPushBatch(ctx context.Context, items []T) int {
	q.access.Lock()
	defer q.access.Unlock()
	if q.closed || ctx.Err() != nil || len(items) == 0 {
		return 0
	}
	count := min(len(items), len(q.items)-q.length)
	wasEmpty := q.length == 0
	for index := range count {
		tail := (q.head + q.length) % len(q.items)
		q.items[tail] = items[index]
		q.length++
	}
	if wasEmpty && count > 0 {
		q.signalNotEmptyLocked()
	}
	return count
}

func (q *dataPacketQueue[T]) Pop(maximumItems int) []T {
	return q.PopInto(nil, maximumItems)
}

func (q *dataPacketQueue[T]) PopInto(items []T, maximumItems int) []T {
	q.access.Lock()
	count := q.length
	if maximumItems > 0 {
		count = min(count, maximumItems)
	}
	if count == 0 {
		q.access.Unlock()
		return items[:0]
	}
	wasFull := q.length == len(q.items)
	if cap(items) < count {
		items = make([]T, count)
	} else {
		items = items[:count]
	}
	for index := range count {
		itemIndex := (q.head + index) % len(q.items)
		items[index] = q.items[itemIndex]
		var zero T
		q.items[itemIndex] = zero
	}
	q.head = (q.head + count) % len(q.items)
	q.length -= count
	if q.length == 0 {
		select {
		case <-q.notEmpty:
		default:
		}
	} else if !q.closed {
		q.signalNotEmptyLocked()
	}
	if wasFull {
		q.signalNotFullLocked()
	}
	q.access.Unlock()
	return items
}

func (q *dataPacketQueue[T]) Wake() <-chan struct{} {
	q.access.Lock()
	defer q.access.Unlock()
	if q.closed {
		return q.notEmpty
	}
	if q.length > 0 {
		q.signalNotEmptyLocked()
	}
	return q.notEmpty
}

func (q *dataPacketQueue[T]) Closed() bool {
	q.access.Lock()
	defer q.access.Unlock()
	return q.closed
}

func (q *dataPacketQueue[T]) Close() {
	q.access.Lock()
	if !q.closed {
		q.closed = true
		close(q.notEmpty)
		q.signalNotFullLocked()
	}
	q.access.Unlock()
}

func (q *dataPacketQueue[T]) Drain(release func(T)) {
	for _, item := range q.Pop(0) {
		if release != nil {
			release(item)
		}
	}
}

func (q *dataPacketQueue[T]) signalNotEmptyLocked() {
	select {
	case q.notEmpty <- struct{}{}:
	default:
	}
}

func (q *dataPacketQueue[T]) signalNotFullLocked() {
	close(q.notFull)
	q.notFull = make(chan struct{})
}
