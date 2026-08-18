package openconnect

import (
	"bytes"
	"context"
	"errors"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
)

type failingAnyConnectDTLSBatchConn struct {
	net.Conn
	err error
}

func (c *failingAnyConnectDTLSBatchConn) WritePackets([][]byte) error { return c.err }
func (c *failingAnyConnectDTLSBatchConn) Close() error                { return nil }

func TestAnyConnectDTLSPacketConnWritesBatch(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	packetConn := newAnyConnectDTLSPacketConn(client)
	defer packetConn.Close()
	batchConn, loaded := packetConn.(interface {
		WritePacketBatchContext(context.Context, [][]byte) error
	})
	if !loaded {
		t.Skip("connected packet batch writes are unavailable on this platform")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	packets := make([][]byte, 16)
	for index := range packets {
		packets[index] = bytes.Repeat([]byte{byte(index + 1)}, index+1)
	}
	if err = batchConn.WritePacketBatchContext(ctx, packets); err != nil {
		t.Fatal(err)
	}

	readBuffer := make([]byte, 64)
	for _, expected := range packets {
		if err = server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		n, _, readErr := server.ReadFromUDP(readBuffer)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if !bytes.Equal(expected, readBuffer[:n]) {
			t.Fatalf("unexpected packet: got %x, want %x", readBuffer[:n], expected)
		}
	}

	canceledContext, cancelWrite := context.WithCancel(context.Background())
	cancelWrite()
	if err = batchConn.WritePacketBatchContext(canceledContext, packets); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled batch write returned %v", err)
	}
	if err = server.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err = server.ReadFromUDP(readBuffer); err == nil {
		t.Fatal("canceled batch write sent a packet")
	}
}

func TestAnyConnectDTLSPacketConnReadsBatch(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	packetConn := newAnyConnectDTLSPacketConn(client)
	defer packetConn.Close()
	batchConn, loaded := packetConn.(interface {
		ReadPacketBatchContext(context.Context) ([][]byte, net.Addr, func(), error)
	})
	if !loaded {
		if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
			t.Fatal("connected packet batch reads are unexpectedly unavailable")
		}
		t.Skip("connected packet batch reads are unavailable on this platform")
	}

	packets := [][]byte{{1}, {2, 2}, {3, 3, 3}}
	for _, packet := range packets {
		if _, err = server.WriteToUDP(packet, client.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	receivedCount := 0
	batched := false
	for receivedCount < len(packets) {
		received, address, release, readErr := batchConn.ReadPacketBatchContext(ctx)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if address.String() != server.LocalAddr().String() {
			release()
			t.Fatalf("unexpected batch source: got %s, want %s", address, server.LocalAddr())
		}
		if len(received) > 1 {
			batched = true
		}
		for _, packet := range received {
			if receivedCount >= len(packets) || !bytes.Equal(packets[receivedCount], packet) {
				release()
				t.Fatalf("unexpected packet %d: got %x", receivedCount, packet)
			}
			receivedCount++
		}
		release()
	}
	if !batched {
		t.Fatal("connected packet batch reader returned only singleton batches")
	}

	canceledContext, cancelRead := context.WithCancel(context.Background())
	cancelRead()
	if _, _, _, err = batchConn.ReadPacketBatchContext(canceledContext); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled batch read returned %v", err)
	}
}

func TestAnyConnectDTLSBatchWriteReportsUnknownDelivery(t *testing.T) {
	writeErr := errors.New("injected batch write failure")
	channel := newAnyConnectDTLS(context.Background(), cstpDTLSNegotiation{
		Compression: anyConnectCompressionNone,
	}, nil)
	channel.conn = &failingAnyConnectDTLSBatchConn{err: writeErr}
	channel.ready.Store(true)
	packetBuffers := []*buf.Buffer{
		newPacketBufferFrom([]byte{0x45, 1}),
		newPacketBufferFrom([]byte{0x45, 2}),
	}
	defer buf.ReleaseMulti(packetBuffers)

	attempted, err := channel.writeDataPacketBuffers(packetBuffers)
	if !attempted {
		t.Fatal("DTLS batch writer did not attempt the batch")
	}
	if !errors.Is(err, ErrDataPacketDeliveryUnknown) || !errors.Is(err, writeErr) {
		t.Fatalf("unexpected batch write error: %v", err)
	}
	if channel.Ready() {
		t.Fatal("failed DTLS batch write left the channel ready")
	}
}
