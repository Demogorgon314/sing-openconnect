package openconnect

import (
	"net"
	"syscall"

	N "github.com/sagernet/sing/common/network"
)

func probeCSTPBaseMTU(connection net.Conn) uint32 {
	systemConnection, isSystemConnection := N.UnwrapReader(connection).(syscall.Conn)
	if !isSystemConnection {
		return 0
	}
	rawConnection, err := systemConnection.SyscallConn()
	if err != nil {
		return 0
	}
	var baseMTU uint32
	err = rawConnection.Control(func(fd uintptr) {
		baseMTU = probeCSTPSocketBaseMTU(fd)
	})
	if err != nil {
		return 0
	}
	return baseMTU
}

func cstpBaseMTUFromSocketInfo(pathMTU uint32, maximumSegmentSize int) uint32 {
	if pathMTU >= 1280 && pathMTU <= cstpMaximumMTU {
		return pathMTU
	}
	const tlsRecordOverhead = 13
	if maximumSegmentSize <= tlsRecordOverhead {
		return 0
	}
	baseMTU := maximumSegmentSize - tlsRecordOverhead
	if baseMTU < 1280 || baseMTU > cstpMaximumMTU {
		return 0
	}
	return uint32(baseMTU)
}
