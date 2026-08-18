package openconnect

import (
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
)

type blockingWriterTestSession struct {
	waitReadyTestSession
	firstWriteStarted chan struct{}
	releaseFirstWrite chan struct{}
	releaseOnce       sync.Once
	access            sync.Mutex
	writeCalls        int
	writtenPackets    [][]byte
}

func (s *blockingWriterTestSession) WriteDataPacketBuffers(packetBuffers []*buf.Buffer) error {
	defer buf.ReleaseMulti(packetBuffers)
	s.access.Lock()
	s.writeCalls++
	writeCall := s.writeCalls
	s.access.Unlock()
	if writeCall == 1 {
		close(s.firstWriteStarted)
		<-s.releaseFirstWrite
	}
	s.access.Lock()
	for _, packetBuffer := range packetBuffers {
		s.writtenPackets = append(s.writtenPackets, append([]byte(nil), packetBuffer.Bytes()...))
	}
	s.access.Unlock()
	return nil
}

func (s *blockingWriterTestSession) unblock() {
	s.releaseOnce.Do(func() {
		close(s.releaseFirstWrite)
	})
}

func (s *blockingWriterTestSession) Close() error {
	s.unblock()
	return nil
}

func publishTestRevisionBehindBlockedWrite(t *testing.T, client *Client, configuration TunnelConfiguration) <-chan struct{} {
	t.Helper()
	configuration, revision := client.setTunnelConfiguration(configuration)
	publishDone := make(chan struct{})
	go func() {
		client.publishTunnelConfigurationEvent(TunnelConfigurationEventPathMTU, revision, configuration)
		close(publishDone)
	}()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	// A queued RWMutex writer prevents new readers. TryRLock failing proves
	// the revision publisher reached the gate behind the active packet write.
	for client.dataPlaneAccess.TryRLock() {
		client.dataPlaneAccess.RUnlock()
		select {
		case <-deadline.C:
			t.Fatal("revision publisher did not queue behind the active write")
		default:
			runtime.Gosched()
		}
	}
	select {
	case <-publishDone:
		t.Fatal("revision publication crossed a blocked data-plane write")
	default:
	}
	return publishDone
}

func TestClientQueuedWriteRejectsStaleRevision(t *testing.T) {
	client := newWaitReadyTestClient(t)
	client.lifecycleAccess.Lock()
	client.outgoingDataPacketWriterDone = make(chan struct{})
	client.lifecycleAccess.Unlock()
	go client.runOutgoingDataPacketWriter()

	session := &blockingWriterTestSession{
		waitReadyTestSession: waitReadyTestSession{
			configuration: TunnelConfiguration{MTU: 1400},
			ready:         true,
		},
		firstWriteStarted: make(chan struct{}),
		releaseFirstWrite: make(chan struct{}),
	}
	t.Cleanup(session.unblock)
	firstRevision := installWaitReadyTestSession(t, client, session, session.configuration)

	firstDone := make(chan error, 1)
	go func() {
		firstDone <- client.WriteDataPacketAtRevision([]byte{1}, firstRevision)
	}()
	select {
	case <-session.firstWriteStarted:
	case <-time.After(time.Second):
		t.Fatal("first write did not reach the session")
	}

	secondDone := make(chan error, 1)
	go func() {
		secondDone <- client.WriteDataPacketAtRevision([]byte{2}, firstRevision)
	}()
	deadline := time.NewTimer(time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	queued := false
	for !queued {
		client.outgoingDataPackets.access.Lock()
		queued = client.outgoingDataPackets.length > 0
		client.outgoingDataPackets.access.Unlock()
		if queued {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("second write was not queued behind the blocked writer")
		case <-ticker.C:
		}
	}

	publishDone := publishTestRevisionBehindBlockedWrite(t, client, TunnelConfiguration{MTU: 1300})
	session.unblock()
	if err := <-firstDone; err != nil {
		t.Fatalf("first write failed: %v", err)
	}
	select {
	case <-publishDone:
	case <-time.After(time.Second):
		t.Fatal("revision publication did not complete after the active write returned")
	}
	if err := <-secondDone; !errors.Is(err, ErrDataChannelNotReady) {
		t.Fatalf("queued stale-revision write was not rejected: %v", err)
	}

	session.access.Lock()
	defer session.access.Unlock()
	if session.writeCalls != 1 || len(session.writtenPackets) != 1 || len(session.writtenPackets[0]) != 1 || session.writtenPackets[0][0] != 1 {
		t.Fatalf("stale packet reached the session: calls=%d packets=%v", session.writeCalls, session.writtenPackets)
	}
}

func TestClientDirectWriteRejectsStaleRevision(t *testing.T) {
	client := newWaitReadyTestClient(t)
	if err := client.WriteDataPacketsDirectAtRevision(nil, 0); err != nil {
		t.Fatalf("empty direct write failed: %v", err)
	}
	session := &blockingWriterTestSession{
		waitReadyTestSession: waitReadyTestSession{
			configuration: TunnelConfiguration{MTU: 1400},
			ready:         true,
		},
		firstWriteStarted: make(chan struct{}),
		releaseFirstWrite: make(chan struct{}),
	}
	t.Cleanup(session.unblock)
	firstRevision := installWaitReadyTestSession(t, client, session, session.configuration)

	firstDone := make(chan error, 1)
	go func() {
		firstDone <- client.WriteDataPacketsDirectAtRevision([][]byte{{1}}, firstRevision)
	}()
	select {
	case <-session.firstWriteStarted:
	case <-time.After(time.Second):
		t.Fatal("first direct write did not reach the session")
	}
	if client.outgoingDataPacketWriteAccess.TryLock() {
		client.outgoingDataPacketWriteAccess.Unlock()
		t.Fatal("direct write did not hold the shared write lock")
	}

	publishDone := publishTestRevisionBehindBlockedWrite(t, client, TunnelConfiguration{MTU: 1300})
	session.unblock()
	if err := <-firstDone; err != nil {
		t.Fatalf("first direct write failed: %v", err)
	}
	select {
	case <-publishDone:
	case <-time.After(time.Second):
		t.Fatal("revision publication did not complete after the direct write returned")
	}
	if err := client.WriteDataPacketsDirectAtRevision([][]byte{{2}}, firstRevision); !errors.Is(err, ErrDataChannelNotReady) {
		t.Fatalf("stale direct write was not rejected: %v", err)
	}

	session.access.Lock()
	defer session.access.Unlock()
	if session.writeCalls != 1 || len(session.writtenPackets) != 1 || len(session.writtenPackets[0]) != 1 || session.writtenPackets[0][0] != 1 {
		t.Fatalf("stale direct packet reached the session: calls=%d packets=%v", session.writeCalls, session.writtenPackets)
	}
}

func TestClientCloseUnblocksDirectWrite(t *testing.T) {
	client := newWaitReadyTestClient(t)
	session := &blockingWriterTestSession{
		waitReadyTestSession: waitReadyTestSession{
			configuration: TunnelConfiguration{MTU: 1400},
			ready:         true,
		},
		firstWriteStarted: make(chan struct{}),
		releaseFirstWrite: make(chan struct{}),
	}
	revision := installWaitReadyTestSession(t, client, session, session.configuration)
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- client.WriteDataPacketsDirectAtRevision([][]byte{{1}}, revision)
	}()
	select {
	case <-session.firstWriteStarted:
	case <-time.After(time.Second):
		t.Fatal("direct write did not reach the session")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- client.Close() }()
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("unexpected direct write result after Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock the direct write")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not drain the direct write gate")
	}
}

var _ clientSession = (*blockingWriterTestSession)(nil)
