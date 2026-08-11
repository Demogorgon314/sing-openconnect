package openconnect

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
)

type waitReadyTestSession struct {
	configuration TunnelConfiguration
	ready         bool
}

func (s *waitReadyTestSession) Start() error { return nil }

func (s *waitReadyTestSession) Done() <-chan error { return nil }

func (s *waitReadyTestSession) WriteDataPackets([][]byte) error { return nil }

func (s *waitReadyTestSession) WriteDataPacketBuffers(packetBuffers []*buf.Buffer) error {
	buf.ReleaseMulti(packetBuffers)
	return nil
}

func (s *waitReadyTestSession) Fail(error) {}

func (s *waitReadyTestSession) Close() error { return nil }

func (s *waitReadyTestSession) Ready() bool { return s.ready }

func (s *waitReadyTestSession) TunnelConfiguration() TunnelConfiguration { return s.configuration }

func TestClientWaitReady(t *testing.T) {
	client := newWaitReadyTestClient(t)
	expected := TunnelConfiguration{
		MTU:       1400,
		Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24")},
	}
	session := &waitReadyTestSession{configuration: expected, ready: true}
	installWaitReadyTestSession(t, client, session, expected)
	configuration, err := client.WaitReady(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if configuration.MTU != expected.MTU || len(configuration.Addresses) != 1 || configuration.Addresses[0] != expected.Addresses[0] {
		t.Fatalf("unexpected ready configuration: %#v", configuration)
	}
	configuration.Addresses[0] = netip.MustParsePrefix("198.51.100.2/24")
	if client.TunnelConfiguration().Addresses[0] != expected.Addresses[0] {
		t.Fatal("WaitReady returned aliased configuration")
	}
}

func TestClientWaitReadyRevisionAdvancesForEquivalentConfiguration(t *testing.T) {
	client := newWaitReadyTestClient(t)
	configuration := TunnelConfiguration{
		MTU:       1400,
		Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24")},
	}
	session := &waitReadyTestSession{configuration: configuration, ready: true}
	firstRevision := installWaitReadyTestSession(t, client, session, configuration)

	revision, err := client.WaitReadyRevision(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if revision != firstRevision {
		t.Fatalf("unexpected first configuration revision: got %d, want %d", revision, firstRevision)
	}
	_, secondRevision := client.setTunnelConfiguration(configuration)
	client.publishTunnelConfigurationEvent(TunnelConfigurationEventPathMTU, secondRevision, configuration)
	if secondRevision <= firstRevision {
		t.Fatalf("equivalent configuration did not advance revision: first=%d second=%d", firstRevision, secondRevision)
	}
	revision, err = client.WaitReadyRevision(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if revision != secondRevision {
		t.Fatalf("unexpected second configuration revision: got %d, want %d", revision, secondRevision)
	}
	if err := client.WriteDataPacketAtRevision([]byte{1}, firstRevision); !errors.Is(err, ErrDataChannelNotReady) {
		t.Fatalf("stale revision write was not rejected: %v", err)
	}
}

func TestClientIncomingDataPacketCarriesConfigurationRevision(t *testing.T) {
	client := newWaitReadyTestClient(t)
	configuration := TunnelConfiguration{MTU: 1400}
	session := &waitReadyTestSession{configuration: configuration, ready: true}
	revision := installWaitReadyTestSession(t, client, session, configuration)

	packetBuffer := buf.NewSize(1)
	_, _ = packetBuffer.Write([]byte{1})
	client.pushIncomingDataPacketContext(context.Background(), session, packetBuffer)
	packet, packetRevision, err := client.ReadDataPacketWithRevision(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if packetRevision != revision || len(packet) != 1 || packet[0] != 1 {
		t.Fatalf("unexpected revision-tagged packet: revision=%d packet=%v", packetRevision, packet)
	}
	batchBuffers := make([]*buf.Buffer, 3)
	for index := range batchBuffers {
		batchBuffers[index] = buf.NewSize(1)
		_, _ = batchBuffers[index].Write([]byte{byte(index + 7)})
	}
	client.pushIncomingDataPacketsContext(context.Background(), session, batchBuffers)
	batch, batchRevision, err := client.ReadDataPacketsWithRevision(context.Background(), len(batchBuffers))
	if err != nil {
		t.Fatal(err)
	}
	if batchRevision != revision || len(batch) != len(batchBuffers) {
		buf.ReleaseMulti(batch)
		t.Fatalf("unexpected revision-tagged batch: revision=%d packets=%d", batchRevision, len(batch))
	}
	for index, packetBuffer := range batch {
		if packetBuffer.Len() != 1 || packetBuffer.Byte(0) != byte(index+7) {
			buf.ReleaseMulti(batch)
			t.Fatalf("unexpected batch packet %d: %v", index, packetBuffer.Bytes())
		}
	}
	buf.ReleaseMulti(batch)
	oldRevisionBuffer := buf.NewSize(1)
	_, _ = oldRevisionBuffer.Write([]byte{2})
	client.pushIncomingDataPacketContext(context.Background(), session, oldRevisionBuffer)
	_, nextRevision := client.setTunnelConfiguration(TunnelConfiguration{MTU: 1300})
	client.publishTunnelConfigurationEvent(TunnelConfigurationEventPathMTU, nextRevision, TunnelConfiguration{MTU: 1300})
	currentRevisionBuffer := buf.NewSize(1)
	_, _ = currentRevisionBuffer.Write([]byte{3})
	client.pushIncomingDataPacketContext(context.Background(), session, currentRevisionBuffer)
	packet, packetRevision, err = client.ReadDataPacketWithRevision(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if packetRevision != nextRevision || len(packet) != 1 || packet[0] != 3 {
		t.Fatalf("stale configuration packet was delivered: revision=%d packet=%v", packetRevision, packet)
	}
	oldSessionBuffer := buf.NewSize(1)
	_, _ = oldSessionBuffer.Write([]byte{4})
	client.pushIncomingDataPacketContext(context.Background(), session, oldSessionBuffer)
	nextSession := &waitReadyTestSession{configuration: configuration, ready: true}
	if !client.setCurrentSession(context.Background(), nextSession) {
		t.Fatal("set replacement test session failed")
	}
	earlyBuffer := buf.NewSize(1)
	_, _ = earlyBuffer.Write([]byte{5})
	client.pushIncomingDataPacketContext(context.Background(), nextSession, earlyBuffer)
	_, replacementRevision := client.setTunnelConfiguration(configuration)
	if !client.publishCurrentSession(context.Background(), nextSession, replacementRevision) {
		t.Fatal("publish replacement test session failed")
	}
	packet, packetRevision, err = client.ReadDataPacketWithRevision(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if packetRevision != replacementRevision || len(packet) != 1 || packet[0] != 5 {
		t.Fatalf("early replacement-session packet was not delivered correctly: revision=%d packet=%v", packetRevision, packet)
	}

	staleSession := &waitReadyTestSession{configuration: configuration, ready: true}
	staleBuffer := buf.NewSize(1)
	_, _ = staleBuffer.Write([]byte{6})
	client.pushIncomingDataPacketContext(context.Background(), staleSession, staleBuffer)
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if _, _, err := client.ReadDataPacketWithRevision(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("packet from stale session was delivered: %v", err)
	}
	if dropped := client.DroppedIncomingDataPackets(); dropped != 3 {
		t.Fatalf("unexpected dropped incoming packet count: got %d, want 3", dropped)
	}
}

func installWaitReadyTestSession(t *testing.T, client *Client, session clientSession, configuration TunnelConfiguration) uint64 {
	t.Helper()
	if !client.setCurrentSession(context.Background(), session) {
		t.Fatal("set test session failed")
	}
	_, revision := client.setTunnelConfiguration(configuration)
	if !client.publishCurrentSession(context.Background(), session, revision) {
		t.Fatal("publish test session failed")
	}
	return revision
}

func TestClientWaitReadyTerminalError(t *testing.T) {
	client := newWaitReadyTestClient(t)
	expected := errors.New("terminal test failure")
	client.setTerminalError(expected)
	_, err := client.WaitReady(context.Background())
	if !errors.Is(err, expected) {
		t.Fatalf("expected terminal error, got %v", err)
	}
}

func TestClientWaitReadyClosed(t *testing.T) {
	client := newWaitReadyTestClient(t)
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := client.WaitReady(context.Background())
	if !errors.Is(err, ErrClientClosed) {
		t.Fatalf("expected closed error, got %v", err)
	}
}

func TestClientWaitReadyContext(t *testing.T) {
	client := newWaitReadyTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	_, err := client.WaitReady(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context deadline, got %v", err)
	}
	if _, err := client.WaitReady(nil); err == nil {
		t.Fatal("expected nil context error")
	}
}

func newWaitReadyTestClient(t *testing.T) *Client {
	t.Helper()
	client, err := NewClient(ClientOptions{
		Server: "https://localhost",
		Cookie: "test-cookie",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}
