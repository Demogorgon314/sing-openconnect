package openconnect

import (
	"context"
	"sync"

	"github.com/sagernet/sing/common/buf"
)

type outboundDataPacket struct {
	session      clientSession
	generation   uint64
	revision     uint64
	packetBuffer *buf.Buffer
	completion   *outboundDataPacketCompletion
}

type outboundDataPacketCompletion struct {
	access              sync.Mutex
	remaining           int
	err                 error
	done                chan error
	singlePacket        [1]outboundDataPacket
	singlePacketBuffers [1]*buf.Buffer
}

func (c *outboundDataPacketCompletion) complete(err error) {
	c.access.Lock()
	if c.err == nil && err != nil {
		c.err = err
	}
	c.remaining--
	if c.remaining == 0 {
		c.done <- c.err
	}
	c.access.Unlock()
}

func (c *outboundDataPacketCompletion) failed() bool {
	c.access.Lock()
	defer c.access.Unlock()
	return c.err != nil
}

func (c *outboundDataPacketCompletion) wait() error {
	return <-c.done
}

func (c *Client) acquireOutboundDataPacketCompletion(remaining int) *outboundDataPacketCompletion {
	completion, loaded := c.outgoingDataPacketCompletions.Get().(*outboundDataPacketCompletion)
	if !loaded {
		completion = &outboundDataPacketCompletion{done: make(chan error, 1)}
	}
	completion.remaining = remaining
	completion.err = nil
	return completion
}

func (c *Client) releaseOutboundDataPacketCompletion(completion *outboundDataPacketCompletion) {
	completion.singlePacket[0] = outboundDataPacket{}
	completion.singlePacketBuffers[0] = nil
	c.outgoingDataPacketCompletions.Put(completion)
}

func (c *Client) enqueueOutboundDataPacketBuffers(
	session clientSession,
	generation uint64,
	revision uint64,
	packetBuffers []*buf.Buffer,
) error {
	completion := c.acquireOutboundDataPacketCompletion(len(packetBuffers))
	defer c.releaseOutboundDataPacketCompletion(completion)
	var packets []outboundDataPacket
	if len(packetBuffers) == 1 {
		packets = completion.singlePacket[:]
	} else {
		packets = make([]outboundDataPacket, len(packetBuffers))
	}
	for index, packetBuffer := range packetBuffers {
		packets[index] = outboundDataPacket{
			session:      session,
			generation:   generation,
			revision:     revision,
			packetBuffer: packetBuffer,
			completion:   completion,
		}
	}
	enqueued := 0
	for enqueued < len(packets) {
		select {
		case c.outgoingDataPacketSlots <- struct{}{}:
		case <-c.outgoingDataPacketClosed:
			failUnqueuedOutboundDataPackets(packets[enqueued:], ErrClientClosed)
			return completion.wait()
		}
		pushed := c.outgoingDataPackets.PushBatch(context.Background(), packets[enqueued:enqueued+1])
		if pushed == 0 {
			<-c.outgoingDataPacketSlots
			failUnqueuedOutboundDataPackets(packets[enqueued:], ErrClientClosed)
			return completion.wait()
		}
		enqueued++
	}
	return completion.wait()
}

func (c *Client) runOutgoingDataPacketWriter() {
	defer close(c.outgoingDataPacketWriterDone)
	packets := make([]outboundDataPacket, 0, cap(c.outgoingDataPacketSlots))
	for {
		packets = c.outgoingDataPackets.PopInto(packets[:0], 0)
		if len(packets) == 0 {
			if c.outgoingDataPackets.Closed() {
				return
			}
			<-c.outgoingDataPackets.Wake()
			continue
		}
		if c.outgoingDataPackets.Closed() {
			c.failQueuedOutboundDataPackets(packets, ErrClientClosed)
			continue
		}
		remainingPackets := packets
		for len(remainingPackets) > 0 {
			completion := remainingPackets[0].completion
			count := 1
			for count < len(remainingPackets) && remainingPackets[count].completion == completion {
				count++
			}
			c.writeQueuedOutboundDataPackets(remainingPackets[:count])
			remainingPackets = remainingPackets[count:]
		}
	}
}

func (c *Client) writeQueuedOutboundDataPackets(packets []outboundDataPacket) {
	completion := packets[0].completion
	if completion.failed() {
		for _, packet := range packets {
			packet.packetBuffer.Release()
			completion.complete(nil)
			<-c.outgoingDataPacketSlots
		}
		return
	}
	// Keep revision/session transitions behind this packet's protocol write.
	c.dataPlaneAccess.RLock()
	if !c.outboundDataPacketCurrent(packets[0]) {
		c.dataPlaneAccess.RUnlock()
		c.failQueuedOutboundDataPackets(packets, ErrDataChannelNotReady)
		return
	}
	var packetBuffers []*buf.Buffer
	if len(packets) == 1 {
		packetBuffers = completion.singlePacketBuffers[:]
	} else {
		packetBuffers = make([]*buf.Buffer, len(packets))
	}
	for index, packet := range packets {
		packetBuffers[index] = packet.packetBuffer
	}
	err := packets[0].session.WriteDataPacketBuffers(packetBuffers)
	if len(packets) == 1 {
		completion.singlePacketBuffers[0] = nil
	}
	c.dataPlaneAccess.RUnlock()
	for range packets {
		completion.complete(err)
		<-c.outgoingDataPacketSlots
	}
}

func (c *Client) outboundDataPacketCurrent(packet outboundDataPacket) bool {
	c.lifecycleAccess.Lock()
	defer c.lifecycleAccess.Unlock()
	return !c.closed && c.terminalError == nil && c.currentSession == packet.session &&
		c.currentSessionGeneration == packet.generation && c.publishedSession == packet.session &&
		c.publishedSessionGeneration == packet.generation && c.publishedSessionRevision == packet.revision &&
		packet.session.Ready()
}

func (c *Client) failQueuedOutboundDataPackets(packets []outboundDataPacket, err error) {
	for _, packet := range packets {
		packet.packetBuffer.Release()
		packet.completion.complete(err)
		<-c.outgoingDataPacketSlots
	}
}

func failUnqueuedOutboundDataPackets(packets []outboundDataPacket, err error) {
	for _, packet := range packets {
		packet.packetBuffer.Release()
		packet.completion.complete(err)
	}
}
