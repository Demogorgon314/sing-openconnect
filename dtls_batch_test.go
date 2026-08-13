package openconnect

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	B "github.com/sagernet/sing/common/bufio"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
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

func BenchmarkAnyConnectDTLSPacketConnWrite(b *testing.B) {
	for _, batch := range []bool{false, true} {
		name := "sequential"
		if batch {
			name = "batch"
		}
		b.Run(name, func(b *testing.B) {
			server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				b.Fatal(err)
			}
			defer server.Close()
			client, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
			if err != nil {
				b.Fatal(err)
			}
			defer client.Close()
			packetConn := newAnyConnectDTLSPacketConn(client)
			batchConn, loaded := packetConn.(interface {
				WritePacketBatchContext(context.Context, [][]byte) error
			})
			if batch && !loaded {
				b.Skip("connected packet batch writes are unavailable on this platform")
			}
			go func() {
				readBuffer := make([]byte, 2048)
				for {
					if _, _, readErr := server.ReadFromUDP(readBuffer); readErr != nil {
						return
					}
				}
			}()
			packets := make([][]byte, 16)
			for index := range packets {
				packets[index] = make([]byte, 1400)
			}
			b.ReportAllocs()
			b.SetBytes(16 * 1400)
			b.ResetTimer()
			for b.Loop() {
				if batch {
					err = batchConn.WritePacketBatchContext(context.Background(), packets)
				} else {
					for _, packet := range packets {
						_, err = client.Write(packet)
						if err != nil {
							break
						}
					}
				}
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkAnyConnectDTLSReceive(b *testing.B) {
	for _, testCase := range []struct {
		name          string
		readBatchSize int
	}{
		{name: "sequential"},
		{name: "batch-2", readBatchSize: 2},
		{name: "batch-4", readBatchSize: 4},
		{name: "batch-8", readBatchSize: 8},
		{name: "batch-16", readBatchSize: 16},
		{name: "batch-32", readBatchSize: 32},
		{name: "batch-64", readBatchSize: 64},
	} {
		b.Run(testCase.name, func(b *testing.B) {
			benchmarkAnyConnectDTLSReceive(b, testCase.readBatchSize)
		})
	}
}

func benchmarkAnyConnectDTLSReceive(b *testing.B, readBatchSize int) {
	b.Helper()

	serverPacketConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	defer serverPacketConn.Close()
	clientConn, err := net.DialUDP("udp4", nil, serverPacketConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		b.Fatal(err)
	}
	packetConn := net.PacketConn(B.NewUnbindPacketConn(clientConn))
	if readBatchSize > 0 {
		packetConn = newAnyConnectDTLSPacketConnWithReadBatchSize(clientConn, readBatchSize)
		if _, loaded := packetConn.(interface {
			ReadPacketBatchContext(context.Context) ([][]byte, net.Addr, func(), error)
		}); !loaded {
			b.Skip("connected packet batch reads are unavailable on this platform")
		}
	}
	defer packetConn.Close()

	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		b.Fatal(err)
	}
	const cipherSuite = dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
	serverResult := make(chan struct {
		conn *dtls.Conn
		err  error
	}, 1)
	go func() {
		server, serverErr := dtls.Server(serverPacketConn, clientConn.LocalAddr(), &dtls.Config{
			Certificates: []tls.Certificate{certificate},
			CipherSuites: []dtls.CipherSuiteID{cipherSuite},
		})
		serverResult <- struct {
			conn *dtls.Conn
			err  error
		}{server, serverErr}
	}()
	client, err := dtls.Client(packetConn, serverPacketConn.LocalAddr(), &dtls.Config{
		InsecureSkipVerify:  true,
		CipherSuites:        []dtls.CipherSuiteID{cipherSuite},
		DedicatedPacketConn: true,
	})
	if err != nil {
		b.Fatal(err)
	}
	defer client.Close()
	result := <-serverResult
	if result.err != nil {
		b.Fatal(result.err)
	}
	server := result.conn
	defer server.Close()
	deadline := time.Now().Add(30 * time.Second)
	if err = client.SetReadDeadline(deadline); err != nil {
		b.Fatal(err)
	}
	if err = server.SetWriteDeadline(deadline); err != nil {
		b.Fatal(err)
	}

	const payloadSize = 1200
	payload := make([]byte, payloadSize)
	binary.BigEndian.PutUint32(payload, uint32(payloadSize))
	for index := 16; index < len(payload); index++ {
		payload[index] = byte(index*31 + 17)
	}
	const maximumInFlightPackets = 64
	windowRead := make(chan struct{})
	writeDone := make(chan error, 1)
	writeContext, cancelWrite := context.WithCancel(context.Background())
	defer cancelWrite()
	b.ReportAllocs()
	b.SetBytes(payloadSize)
	b.ResetTimer()
	go func() {
		for base := 0; base < b.N; base += maximumInFlightPackets {
			count := min(maximumInFlightPackets, b.N-base)
			for offset := range count {
				sequence := uint64(base + offset)
				binary.BigEndian.PutUint64(payload[4:12], sequence)
				binary.BigEndian.PutUint32(payload[12:16], ^uint32(sequence))
				if _, writeErr := server.Write(payload); writeErr != nil {
					writeDone <- writeErr
					return
				}
			}
			select {
			case <-windowRead:
			case <-writeContext.Done():
				writeDone <- writeContext.Err()
				return
			}
		}
		writeDone <- nil
	}()

	readBuffer := make([]byte, payloadSize+64)
	for expected := 0; expected < b.N; expected++ {
		count, readErr := client.Read(readBuffer)
		if readErr != nil {
			b.Fatalf("read packet %d: %v", expected, readErr)
		}
		if count != payloadSize || binary.BigEndian.Uint32(readBuffer) != payloadSize ||
			binary.BigEndian.Uint64(readBuffer[4:12]) != uint64(expected) ||
			binary.BigEndian.Uint32(readBuffer[12:16]) != ^uint32(expected) {
			b.Fatalf("invalid packet %d", expected)
		}
		for index := 16; index < count; index++ {
			if readBuffer[index] != byte(index*31+17) {
				b.Fatalf("packet %d changed at offset %d", expected, index)
			}
		}
		if (expected+1)%maximumInFlightPackets == 0 || expected+1 == b.N {
			windowRead <- struct{}{}
		}
	}
	if err = <-writeDone; err != nil {
		b.Fatal(err)
	}
	b.StopTimer()
}
