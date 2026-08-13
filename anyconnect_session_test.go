package openconnect

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
)

func TestAnyConnectCSTPWriteFailureMarksDeliveryUnknown(t *testing.T) {
	clientConnection, serverConnection := net.Pipe()
	if err := serverConnection.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	session := &anyConnectCSTPSession{
		ctx:    ctx,
		cancel: cancel,
		client: new(Client),
		transport: &cstpConnectedTransport{
			connection: tls.Client(clientConnection, &tls.Config{InsecureSkipVerify: true}), //nolint:gosec // closed in-memory test connection
		},
		configuration: TunnelConfiguration{MTU: 1400},
		done:          make(chan error, 1),
	}
	session.ready.Store(true)
	session.active.Store(true)

	err := session.WriteDataPacket([]byte{0x45})
	if !errors.Is(err, ErrDataPacketDeliveryUnknown) {
		t.Fatalf("CSTP write failure was not marked as delivery-unknown: %v", err)
	}
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("CSTP write failure did not preserve its cause: %v", err)
	}
	if session.Ready() {
		t.Fatal("failed CSTP session remained ready")
	}
}
