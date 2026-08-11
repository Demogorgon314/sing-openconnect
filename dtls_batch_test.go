package openconnect

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

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
	packets := [][]byte{{1}, {2, 2}, {3, 3, 3}}
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
