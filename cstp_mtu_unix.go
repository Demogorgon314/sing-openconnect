//go:build aix || darwin || dragonfly || freebsd || netbsd || openbsd || solaris

package openconnect

import "golang.org/x/sys/unix"

func probeCSTPSocketBaseMTU(fd uintptr) uint32 {
	maximumSegmentSize, _ := unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG)
	return cstpBaseMTUFromSocketInfo(0, maximumSegmentSize)
}
