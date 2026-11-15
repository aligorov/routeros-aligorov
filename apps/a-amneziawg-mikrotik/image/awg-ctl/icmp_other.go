//go:build !linux

package main

import (
	"context"
	"fmt"
	"time"
)

func icmpPingHost(_ context.Context, _ string, _ int, _ string, _ time.Duration) (int64, string, error) {
	return 0, "", fmt.Errorf("ICMP ping probe supported only on Linux runtime")
}
