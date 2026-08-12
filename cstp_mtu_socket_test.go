//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package openconnect

import (
	"net"
	"testing"
)

type wrappedCSTPConnection struct {
	net.Conn
}

func (c *wrappedCSTPConnection) Upstream() any {
	return c.Conn
}

func (*wrappedCSTPConnection) ReaderReplaceable() bool {
	return true
}

func TestProbeCSTPBaseMTU(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	acceptError := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			acceptError <- acceptErr
			return
		}
		accepted <- connection
	}()
	connection, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	select {
	case acceptedConnection := <-accepted:
		defer acceptedConnection.Close()
	case err = <-acceptError:
		t.Fatal(err)
	}
	if baseMTU := probeCSTPBaseMTU(&wrappedCSTPConnection{connection}); baseMTU < 1280 || baseMTU > cstpMaximumMTU {
		t.Fatalf("invalid probed base MTU: %d", baseMTU)
	}
}
