//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package openconnect

func probeCSTPSocketBaseMTU(uintptr) uint32 {
	return 0
}
