package openconnect

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
	B "github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

type anyConnectDTLSBatchPacketConn struct {
	N.NetPacketConn
	conn        net.Conn
	batchWriter N.ConnectedPacketBatchWriter
}

type anyConnectDTLSBatchReadPacketConn struct {
	N.NetPacketConn
	conn        net.Conn
	batchReader N.ConnectedPacketBatchReadWaiter
	readAccess  sync.Mutex
}

type anyConnectDTLSBatchReadWritePacketConn struct {
	*anyConnectDTLSBatchReadPacketConn
	batchWriter N.ConnectedPacketBatchWriter
}

func newAnyConnectDTLSPacketConn(conn net.Conn) net.PacketConn {
	packetConn := B.NewUnbindPacketConn(conn)
	batchReader, readLoaded := B.CreateConnectedPacketBatchReadWaiter(packetConn)
	if readLoaded {
		batchReader.InitializeReadWaiter(N.ReadWaitOptions{
			MTU:       8192,
			BatchSize: B.DefaultPacketReadBatchSize,
		})
	}
	batchWriter, loaded := B.CreateConnectedPacketBatchWriter(packetConn)
	switch {
	case readLoaded && loaded:
		return &anyConnectDTLSBatchReadWritePacketConn{
			anyConnectDTLSBatchReadPacketConn: &anyConnectDTLSBatchReadPacketConn{
				NetPacketConn: packetConn,
				conn:          conn,
				batchReader:   batchReader,
			},
			batchWriter: batchWriter,
		}
	case readLoaded:
		return &anyConnectDTLSBatchReadPacketConn{
			NetPacketConn: packetConn,
			conn:          conn,
			batchReader:   batchReader,
		}
	case loaded:
		return &anyConnectDTLSBatchPacketConn{
			NetPacketConn: packetConn,
			conn:          conn,
			batchWriter:   batchWriter,
		}
	default:
		return packetConn
	}
}

func (c *anyConnectDTLSBatchPacketConn) WritePacketBatchContext(ctx context.Context, packets [][]byte) error {
	return writeAnyConnectDTLSPacketBatchContext(ctx, c.conn, c.batchWriter, packets)
}

func (c *anyConnectDTLSBatchReadWritePacketConn) WritePacketBatchContext(ctx context.Context, packets [][]byte) error {
	return writeAnyConnectDTLSPacketBatchContext(ctx, c.conn, c.batchWriter, packets)
}

func writeAnyConnectDTLSPacketBatchContext(ctx context.Context, conn net.Conn, batchWriter N.ConnectedPacketBatchWriter, packets [][]byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	buffers := make([]*buf.Buffer, len(packets))
	for index, packet := range packets {
		buffers[index] = buf.As(packet)
	}

	callbackDone := make(chan struct{})
	var deadlineErr error
	stop := context.AfterFunc(ctx, func() {
		deadlineErr = conn.SetWriteDeadline(time.Unix(1, 0))
		close(callbackDone)
	})
	err := batchWriter.WriteConnectedPacketBatch(buffers)
	if stop() {
		return err
	}
	<-callbackDone
	resetErr := conn.SetWriteDeadline(time.Time{})
	if err == nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			err = ctxErr
		} else if deadlineErr != nil {
			err = deadlineErr
		} else if resetErr != nil {
			err = resetErr
		}
	}
	return err
}

func (c *anyConnectDTLSBatchReadPacketConn) ReadPacketBatchContext(ctx context.Context) ([][]byte, net.Addr, func(), error) {
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, err
	}

	callbackDone := make(chan struct{})
	var deadlineErr error
	stop := context.AfterFunc(ctx, func() {
		deadlineErr = c.conn.SetReadDeadline(time.Unix(1, 0))
		close(callbackDone)
	})
	buffers, _, err := c.batchReader.WaitReadConnectedPackets()
	if !stop() {
		<-callbackDone
		resetErr := c.conn.SetReadDeadline(time.Time{})
		if err == nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				err = ctxErr
			} else if deadlineErr != nil {
				err = deadlineErr
			} else if resetErr != nil {
				err = resetErr
			}
		}
	}
	if err != nil {
		buf.ReleaseMulti(buffers)
		return nil, nil, nil, err
	}
	packets := make([][]byte, len(buffers))
	for index, buffer := range buffers {
		packets[index] = buffer.Bytes()
	}
	var releaseOnce sync.Once
	return packets, c.conn.RemoteAddr(), func() {
		releaseOnce.Do(func() {
			buf.ReleaseMulti(buffers)
		})
	}, nil
}
