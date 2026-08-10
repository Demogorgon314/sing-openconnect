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
	client.setTunnelConfiguration(expected)
	client.lifecycleAccess.Lock()
	client.currentSession = session
	client.publishedSession = session
	client.signalStateChangedLocked()
	client.lifecycleAccess.Unlock()
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
