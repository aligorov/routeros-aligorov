//go:build !linux

package main

import (
	"net"
	"time"
)

func sockMarkDialer(_ int) net.Dialer {
	return net.Dialer{Timeout: 2 * time.Second}
}

func sockBindDialer(_ string, _ int, timeout time.Duration) net.Dialer {
	return net.Dialer{Timeout: timeout}
}
