//go:build linux

package main

import (
	"net"
	"syscall"
	"time"
)

func sockMarkDialer(mark int) net.Dialer {
	return sockBindDialer("", mark, 2*time.Second)
}

func sockBindDialer(iface string, mark int, timeout time.Duration) net.Dialer {
	if iface == "" && mark == 0 {
		return net.Dialer{Timeout: timeout}
	}
	return net.Dialer{
		Timeout: timeout,
		Control: func(_, _ string, c syscall.RawConn) error {
			var setErr error
			if err := c.Control(func(fd uintptr) {
				if iface != "" {
					if err := syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface); err != nil {
						setErr = err
						return
					}
				}
				if mark != 0 {
					if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark); err != nil {
						setErr = err
						return
					}
				}
			}); err != nil {
				return err
			}
			return setErr
		},
	}
}
