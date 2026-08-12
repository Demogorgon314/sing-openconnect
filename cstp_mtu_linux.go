//go:build linux

package openconnect

import "golang.org/x/sys/unix"

func probeCSTPSocketBaseMTU(fd uintptr) uint32 {
	var pathMTU uint32
	if info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO); err == nil {
		pathMTU = info.Pmtu
	}
	maximumSegmentSize, _ := unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG)
	return cstpBaseMTUFromSocketInfo(pathMTU, maximumSegmentSize)
}
