package openconnect

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/pion/dtls/v3"
)

type anyConnectDTLSChannel struct {
	ctx             context.Context
	cancel          context.CancelFunc
	negotiation     cstpDTLSNegotiation
	deliver         func([]*buf.Buffer)
	done            chan error
	doneOnce        sync.Once
	access          sync.RWMutex
	writeAccess     sync.Mutex
	waitGroup       sync.WaitGroup
	conn            net.Conn
	started         bool
	closed          bool
	closeErr        error
	ready           atomic.Bool
	lastReceived    atomic.Int64
	lastTransmitted atomic.Int64
	lastDPD         atomic.Int64
	lastRekey       atomic.Int64
	detectedMTU     atomic.Int64
}

func newAnyConnectDTLS(
	ctx context.Context,
	negotiation cstpDTLSNegotiation,
	deliver func([]*buf.Buffer),
) *anyConnectDTLSChannel {
	channelCtx, cancel := context.WithCancel(ctx)
	return &anyConnectDTLSChannel{
		ctx:         channelCtx,
		cancel:      cancel,
		negotiation: negotiation,
		deliver:     deliver,
		done:        make(chan error, 1),
	}
}

func (c *anyConnectDTLSChannel) Start() error {
	c.access.Lock()
	if c.started {
		c.access.Unlock()
		return E.New("DTLS channel already started")
	}
	if c.closed {
		c.access.Unlock()
		return E.New("DTLS channel is closed")
	}
	c.started = true
	c.access.Unlock()

	conn, err := c.connect()
	if err != nil {
		c.terminate(err)
		return err
	}
	detectedMTU, err := detectAnyConnectDTLSMTU(c.ctx, conn, c.negotiation.MinimumMTU, c.negotiation.MTU)
	if err != nil {
		closeErr := conn.Close()
		if E.IsClosed(closeErr) {
			closeErr = nil
		}
		err = E.Errors(err, closeErr)
		c.terminate(err)
		return err
	}
	if detectedMTU > 0 {
		c.detectedMTU.Store(int64(detectedMTU))
	}
	now := time.Now().UnixNano()
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		closeErr := conn.Close()
		if closeErr != nil {
			return E.Cause(closeErr, "close DTLS channel after concurrent shutdown")
		}
		return E.New("DTLS channel closed during startup")
	}
	timersConfigured := c.negotiation.DPD > 0 || c.negotiation.Keepalive > 0 ||
		c.negotiation.Rekey > 0 && c.negotiation.RekeyMethod != "" && c.negotiation.RekeyMethod != "none"
	workerCount := 1
	if timersConfigured {
		workerCount++
	}
	c.conn = conn
	c.waitGroup.Add(workerCount)
	c.ready.Store(true)
	c.lastReceived.Store(now)
	c.lastTransmitted.Store(now)
	c.lastRekey.Store(now)
	c.access.Unlock()

	go c.readLoop()
	if timersConfigured {
		go c.timerLoop()
	}
	return nil
}

func (c *anyConnectDTLSChannel) Ready() bool {
	return c.ready.Load()
}

func (c *anyConnectDTLSChannel) DetectedMTU() int {
	return int(c.detectedMTU.Load())
}

func (c *anyConnectDTLSChannel) WriteDataPacket(payload []byte) error {
	packetBuffer := newPacketBufferFrom(payload)
	defer packetBuffer.Release()
	return c.WriteDataPacketBuffer(&packetBuffer)
}

func (c *anyConnectDTLSChannel) WriteDataPacketBuffer(packetBuffer **buf.Buffer) error {
	packetType := cstpPacketData
	outgoingBuffer := packetBuffer
	var compressedPacket *buf.Buffer
	compressedPacket, compressed := compressAnyConnectStatelessPacket(c.negotiation.Compression, (*packetBuffer).Bytes())
	if compressed {
		outgoingBuffer = &compressedPacket
		packetType = cstpPacketCompressed
	}
	*outgoingBuffer = requirePacketBufferCapacity(*outgoingBuffer, 1, 0)
	header := (*outgoingBuffer).ExtendHeader(1)
	header[0] = packetType
	err := c.writePacket((*outgoingBuffer).Bytes())
	(*outgoingBuffer).Advance(1)
	if compressedPacket != nil {
		compressedPacket.Release()
	}
	return err
}

func (c *anyConnectDTLSChannel) writeDataPacketBuffers(packetBuffers []*buf.Buffer) (bool, error) {
	if len(packetBuffers) < 2 || c.negotiation.Compression != anyConnectCompressionNone {
		return false, nil
	}
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	if !c.ready.Load() {
		return false, nil
	}
	c.access.RLock()
	conn := c.conn
	c.access.RUnlock()
	batchConn, loaded := conn.(interface{ WritePackets([][]byte) error })
	if !loaded {
		return false, nil
	}

	packets := make([][]byte, len(packetBuffers))
	for index, packetBuffer := range packetBuffers {
		packetBuffers[index] = requirePacketBufferCapacity(packetBuffer, 1, 0)
		header := packetBuffers[index].ExtendHeader(1)
		header[0] = cstpPacketData
		packets[index] = packetBuffers[index].Bytes()
	}
	err := batchConn.WritePackets(packets)
	for _, packetBuffer := range packetBuffers {
		packetBuffer.Advance(1)
	}
	if err != nil {
		wrappedErr := E.Cause(err, "write DTLS packet batch")
		c.terminate(wrappedErr)
		return true, wrappedErr
	}
	c.lastTransmitted.Store(time.Now().UnixNano())
	return true, nil
}

func (c *anyConnectDTLSChannel) writePacket(packet []byte) error {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	if !c.ready.Load() {
		return E.New("DTLS channel is not ready")
	}
	c.access.RLock()
	conn := c.conn
	c.access.RUnlock()
	if conn == nil {
		return E.New("DTLS channel has no active connection")
	}
	n, err := conn.Write(packet)
	if err != nil {
		wrappedErr := E.Cause(err, "write DTLS packet")
		c.terminate(wrappedErr)
		return wrappedErr
	}
	if n != len(packet) {
		shortWriteErr := E.New("short DTLS packet write: wrote ", n, " of ", len(packet), " bytes")
		c.terminate(shortWriteErr)
		return shortWriteErr
	}
	c.lastTransmitted.Store(time.Now().UnixNano())
	return nil
}

func (c *anyConnectDTLSChannel) readLoop() {
	defer c.waitGroup.Done()
	maximumPayloadSize := max(16384, c.negotiation.MTU)
	bufferSize := maximumPayloadSize + 1
	for {
		c.access.RLock()
		conn := c.conn
		c.access.RUnlock()
		if conn == nil {
			return
		}
		packetBuffers, readErr := readAnyConnectDTLSPackets(conn, bufferSize)
		if len(packetBuffers) == 0 && readErr == nil {
			continue
		}
		c.lastReceived.Store(time.Now().UnixNano())
		deliverable := make([]*buf.Buffer, 0, len(packetBuffers))
		for index, packetBuffer := range packetBuffers {
			delivery, stop, err := c.handleIncomingPacket(packetBuffer, maximumPayloadSize)
			if delivery != nil {
				deliverable = append(deliverable, delivery)
			}
			if stop {
				buf.ReleaseMulti(deliverable)
				buf.ReleaseMulti(packetBuffers[index+1:])
				if err != nil && c.ctx.Err() == nil && err != io.EOF {
					c.terminate(E.Cause(err, "read DTLS packet"))
				} else {
					c.terminate(nil)
				}
				return
			}
		}
		if len(deliverable) > 0 {
			if c.deliver != nil {
				c.deliver(deliverable)
			} else {
				buf.ReleaseMulti(deliverable)
			}
		}
		if readErr != nil {
			if c.ctx.Err() == nil && readErr != io.EOF {
				c.terminate(E.Cause(readErr, "read DTLS packet"))
			} else {
				c.terminate(nil)
			}
			return
		}
	}
}

func readAnyConnectDTLSPackets(conn net.Conn, bufferSize int) ([]*buf.Buffer, error) {
	if bufferReader, loaded := conn.(interface {
		ReadApplicationDataBuffers() ([]dtls.ApplicationDataBuffer, error)
	}); loaded {
		applicationBuffers, err := bufferReader.ReadApplicationDataBuffers()
		packetBuffers := make([]*buf.Buffer, len(applicationBuffers))
		for index, applicationBuffer := range applicationBuffers {
			if packetBuffer, ok := applicationBuffer.(*buf.Buffer); ok {
				packetBuffers[index] = packetBuffer
				continue
			}
			data := applicationBuffer.Bytes()
			packetBuffer := buf.NewSize(len(data))
			copy(packetBuffer.Extend(len(data)), data)
			applicationBuffer.Release()
			packetBuffers[index] = packetBuffer
		}
		return packetBuffers, err
	}
	if batchReader, loaded := conn.(interface {
		ReadPackets() ([][]byte, error)
	}); loaded {
		packets, err := batchReader.ReadPackets()
		packetBuffers := make([]*buf.Buffer, len(packets))
		for index, packet := range packets {
			packetBuffers[index] = buf.As(packet)
		}
		return packetBuffers, err
	}
	packetBuffer := newPacketBuffer(bufferSize)
	count, err := conn.Read(packetBuffer.FreeBytes())
	if count == 0 {
		packetBuffer.Release()
		return nil, err
	}
	packetBuffer.Extend(count)
	return []*buf.Buffer{packetBuffer}, err
}

func (c *anyConnectDTLSChannel) handleIncomingPacket(packetBuffer *buf.Buffer, maximumPayloadSize int) (*buf.Buffer, bool, error) {
	switch packetBuffer.Byte(0) {
	case cstpPacketData:
		packetBuffer.Advance(1)
		return packetBuffer, false, nil
	case cstpPacketDPDRequest:
		packetBuffer.Release()
		err := c.writePacket([]byte{cstpPacketDPDResponse})
		if err != nil {
			return nil, true, err
		}
		return nil, false, nil
	case cstpPacketDPDResponse, cstpPacketKeepalive:
		packetBuffer.Release()
		return nil, false, nil
	case cstpPacketCompressed:
		if c.negotiation.Compression == anyConnectCompressionNone {
			packetBuffer.Release()
			return nil, true, E.Extend(ErrProtocolNotSupported, "received compressed DTLS packet without negotiated compression")
		}
		packetBuffer.Advance(1)
		decompressedPacket, decompressErr := decompressAnyConnectStatelessPacket(c.negotiation.Compression, packetBuffer.Bytes(), maximumPayloadSize)
		packetBuffer.Release()
		if decompressErr != nil {
			if c.negotiation.Logger != nil {
				c.negotiation.Logger.DebugContext(c.ctx, "Ignoring invalid ", c.negotiation.Compression.String(), "-compressed DTLS packet: ", decompressErr)
			}
			return nil, false, nil
		}
		return decompressedPacket, false, nil
	default:
		packetBuffer.Release()
		// Upstream dtls_mainloop ignores unknown packet types because some OpenSSL versions return out-of-order record garbage in non-blocking mode.
		return nil, false, nil
	}
}

func (c *anyConnectDTLSChannel) Close() error {
	c.terminate(nil)
	c.waitGroup.Wait()
	c.access.RLock()
	closeErr := c.closeErr
	c.access.RUnlock()
	return closeErr
}

func (c *anyConnectDTLSChannel) Done() <-chan error {
	return c.done
}

func (c *anyConnectDTLSChannel) terminate(err error) {
	c.doneOnce.Do(func() {
		c.access.Lock()
		c.ready.Store(false)
		c.closed = true
		conn := c.conn
		c.conn = nil
		c.access.Unlock()
		c.cancel()
		if conn != nil {
			closeErr := conn.Close()
			if closeErr != nil && !E.IsClosed(closeErr) {
				wrappedCloseErr := E.Cause(closeErr, "close DTLS connection")
				c.access.Lock()
				c.closeErr = wrappedCloseErr
				c.access.Unlock()
				if err == nil {
					err = wrappedCloseErr
				} else {
					err = E.Errors(err, wrappedCloseErr)
				}
			}
		}
		if err != nil {
			c.done <- err
		}
		close(c.done)
	})
}
