package openconnect

import (
	"context"
	"net"
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

func newAnyConnectDTLSPacketConn(conn net.Conn) net.PacketConn {
	packetConn := B.NewUnbindPacketConn(conn)
	batchWriter, loaded := B.CreateConnectedPacketBatchWriter(packetConn)
	if !loaded {
		return packetConn
	}
	return &anyConnectDTLSBatchPacketConn{
		NetPacketConn: packetConn,
		conn:          conn,
		batchWriter:   batchWriter,
	}
}

func (c *anyConnectDTLSBatchPacketConn) WritePacketBatchContext(ctx context.Context, packets [][]byte) error {
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
		deadlineErr = c.conn.SetWriteDeadline(time.Unix(1, 0))
		close(callbackDone)
	})
	err := c.batchWriter.WriteConnectedPacketBatch(buffers)
	if stop() {
		return err
	}
	<-callbackDone
	resetErr := c.conn.SetWriteDeadline(time.Time{})
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
