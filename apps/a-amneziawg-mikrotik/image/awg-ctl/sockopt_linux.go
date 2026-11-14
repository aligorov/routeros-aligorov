//go:build linux

package main

import (
	"net"
	"syscall"
)

func sockMarkDialer(mark int) net.Dialer {
	if mark == 0 {
		return net.Dialer{Timeout: 2 * 1e9}
	}
	return net.Dialer{
		Timeout: 2 * 1e9,
		Control: func(_, _ string, c syscall.RawConn) error {
			var setErr error
			if err := c.Control(func(fd uintptr) {
				setErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark)
			}); err != nil {
				return err
			}
			return setErr
		},
	}
}
