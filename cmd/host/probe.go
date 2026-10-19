package main

import (
	"errors"
	"net"
	"strconv"
	"time"
)

// Probe without initializing identity, policy, journal or any server. The health
// listener remains loopback-only, so a kubelet HTTP/TCP pod-IP probe cannot reach it.
func healthProbe(address string) error {
	host, port, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	n, portErr := strconv.Atoi(port)
	if err != nil || ip == nil || !ip.IsLoopback() || portErr != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return errors.New("health-probe requires a literal loopback IP and canonical nonzero port")
	}
	connection, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return errors.New("health listener unavailable")
	}
	return connection.Close()
}
