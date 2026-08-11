package openconnect

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"

	"github.com/sagernet/sing/common/buf"
)

const anyConnectBenchmarkPacketMagic = 0x41434e42

type benchmarkPacketSession struct {
	configuration TunnelConfiguration
	expected      uint64
	received      uint64
}

func (s *benchmarkPacketSession) Start() error { return nil }

func (s *benchmarkPacketSession) Done() <-chan error { return nil }

func (s *benchmarkPacketSession) WriteDataPackets(packets [][]byte) error {
	for _, packet := range packets {
		if err := validateAnyConnectBenchmarkPacket(packet, s.expected); err != nil {
			return err
		}
		s.expected++
		s.received++
	}
	return nil
}

func (s *benchmarkPacketSession) WriteDataPacketBuffers(packetBuffers []*buf.Buffer) error {
	defer buf.ReleaseMulti(packetBuffers)
	for _, packetBuffer := range packetBuffers {
		if err := validateAnyConnectBenchmarkPacket(packetBuffer.Bytes(), s.expected); err != nil {
			return err
		}
		s.expected++
		s.received++
	}
	return nil
}

func (s *benchmarkPacketSession) Fail(error) {}

func (s *benchmarkPacketSession) Close() error { return nil }

func (s *benchmarkPacketSession) Ready() bool { return true }

func (s *benchmarkPacketSession) TunnelConfiguration() TunnelConfiguration { return s.configuration }

// BenchmarkAnyConnectP1OutboundPipeline measures one packet through the public
// client copy, queue, completion, revision gate, and protocol-session write.
// The session validates every packet before acknowledging the write.
func BenchmarkAnyConnectP1OutboundPipeline(b *testing.B) {
	for _, packetSize := range []int{128, 512, 1200, 1400} {
		b.Run(fmt.Sprintf("%dB", packetSize), func(b *testing.B) {
			client, err := NewClient(ClientOptions{
				Server:      "https://localhost",
				Cookie:      "benchmark-cookie",
				QueueLength: 64,
			})
			if err != nil {
				b.Fatal(err)
			}
			client.lifecycleAccess.Lock()
			client.outgoingDataPacketWriterDone = make(chan struct{})
			client.lifecycleAccess.Unlock()
			go client.runOutgoingDataPacketWriter()
			b.Cleanup(func() {
				if closeErr := client.Close(); closeErr != nil {
					b.Errorf("close benchmark client: %v", closeErr)
				}
			})

			configuration := TunnelConfiguration{
				MTU:       1400,
				Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24")},
			}
			session := &benchmarkPacketSession{configuration: configuration}
			if !client.setCurrentSession(context.Background(), session) {
				b.Fatal("install benchmark session")
			}
			_, revision := client.setTunnelConfiguration(configuration)
			if !client.publishCurrentSession(context.Background(), session, revision) {
				b.Fatal("publish benchmark session")
			}

			packet := newAnyConnectBenchmarkPacket(packetSize)
			b.ReportAllocs()
			b.SetBytes(int64(packetSize))
			b.ResetTimer()
			for index := 0; index < b.N; index++ {
				setAnyConnectBenchmarkPacketSequence(packet, uint64(index))
				if err = client.WriteDataPacketAtRevision(packet, revision); err != nil {
					b.Fatalf("write packet %d: %v", index, err)
				}
			}
			b.StopTimer()
			if session.received != uint64(b.N) || session.expected != uint64(b.N) {
				b.Fatalf("packet accounting mismatch: received=%d expected=%d benchmark=%d", session.received, session.expected, b.N)
			}
		})
	}
}

// BenchmarkAnyConnectP4PacketBufferCopy isolates the payload copy and headroom
// allocation used before packets enter the outbound queue.
func BenchmarkAnyConnectP4PacketBufferCopy(b *testing.B) {
	for _, packetSize := range []int{128, 512, 1200, 1400} {
		b.Run(fmt.Sprintf("%dB", packetSize), func(b *testing.B) {
			packet := newAnyConnectBenchmarkPacket(packetSize)
			b.ReportAllocs()
			b.SetBytes(int64(packetSize))
			b.ResetTimer()
			for b.Loop() {
				packetBuffer := newPacketBufferFrom(packet)
				if packetBuffer.Start() < PacketHeadroom || !bytes.Equal(packetBuffer.Bytes(), packet) {
					packetBuffer.Release()
					b.Fatal("packet buffer changed payload or lost required headroom")
				}
				packetBuffer.Release()
			}
		})
	}
}

// BenchmarkAnyConnectP5QueueWakeup forces an empty/full transition per item so
// queue notification changes cannot hide lost, duplicated, or reordered work.
func BenchmarkAnyConnectP5QueueWakeup(b *testing.B) {
	queue := newDataPacketQueue[uint64](1)
	ctx, cancel := context.WithCancel(context.Background())
	b.Cleanup(cancel)
	start := make(chan struct{})
	producerDone := make(chan error, 1)
	go func() {
		<-start
		item := []uint64{0}
		for index := 0; index < b.N; index++ {
			item[0] = uint64(index)
			if queue.PushBatch(ctx, item) != 1 {
				producerDone <- fmt.Errorf("push item %d failed", index)
				return
			}
		}
		producerDone <- nil
	}()

	b.ReportAllocs()
	b.ResetTimer()
	close(start)
	for expected := 0; expected < b.N; {
		items := queue.Pop(1)
		if len(items) == 0 {
			select {
			case <-queue.Wake():
				continue
			case <-ctx.Done():
				b.Fatal(ctx.Err())
			}
		}
		if len(items) != 1 || items[0] != uint64(expected) {
			b.Fatalf("queue sequence mismatch at %d: %v", expected, items)
		}
		expected++
	}
	if err := <-producerDone; err != nil {
		b.Fatal(err)
	}
	b.StopTimer()
	queue.Close()
}

func newAnyConnectBenchmarkPacket(size int) []byte {
	if size < 24 {
		panic("AnyConnect benchmark packet must be at least 24 bytes")
	}
	packet := make([]byte, size)
	binary.BigEndian.PutUint32(packet[0:4], anyConnectBenchmarkPacketMagic)
	binary.BigEndian.PutUint32(packet[4:8], uint32(size))
	for index := 24; index < len(packet); index++ {
		packet[index] = byte(index*31 + 17)
	}
	return packet
}

func setAnyConnectBenchmarkPacketSequence(packet []byte, sequence uint64) {
	binary.BigEndian.PutUint64(packet[8:16], sequence)
	binary.BigEndian.PutUint64(packet[16:24], ^sequence)
}

func validateAnyConnectBenchmarkPacket(packet []byte, expectedSequence uint64) error {
	if len(packet) < 24 || binary.BigEndian.Uint32(packet[0:4]) != anyConnectBenchmarkPacketMagic {
		return fmt.Errorf("invalid benchmark packet header at sequence %d", expectedSequence)
	}
	if int(binary.BigEndian.Uint32(packet[4:8])) != len(packet) {
		return fmt.Errorf("benchmark packet length mismatch at sequence %d", expectedSequence)
	}
	sequence := binary.BigEndian.Uint64(packet[8:16])
	if sequence != expectedSequence || binary.BigEndian.Uint64(packet[16:24]) != ^sequence {
		return fmt.Errorf("benchmark packet sequence mismatch: got %d, want %d", sequence, expectedSequence)
	}
	for index := 24; index < len(packet); index++ {
		if packet[index] != byte(index*31+17) {
			return fmt.Errorf("benchmark packet payload changed at sequence %d offset %d", sequence, index)
		}
	}
	return nil
}

var _ clientSession = (*benchmarkPacketSession)(nil)
