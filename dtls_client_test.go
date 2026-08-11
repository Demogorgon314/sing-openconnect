package openconnect

import "testing"

type dtlsReadBufferRecorder struct {
	size int
}

func (c *dtlsReadBufferRecorder) SetReadBuffer(size int) error {
	c.size = size
	return nil
}

type dtlsReadBufferWrapper struct {
	upstream any
}

func (c *dtlsReadBufferWrapper) Upstream() any {
	return c.upstream
}

func TestAnyConnectDTLSReadBufferThroughWrappedConnection(t *testing.T) {
	recorder := new(dtlsReadBufferRecorder)
	wrapped := &dtlsReadBufferWrapper{upstream: recorder}

	setAnyConnectDTLSReadBuffer(wrapped)
	if recorder.size != anyConnectDTLSReadBuffer {
		t.Fatalf("unexpected DTLS read buffer size: got %d, want %d", recorder.size, anyConnectDTLSReadBuffer)
	}
}
