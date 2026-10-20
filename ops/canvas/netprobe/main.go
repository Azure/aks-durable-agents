// Command netprobe is a diagnostic-only numeric-address TCP control for kind.
package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

func validAddress(address string) bool {
	host, port, err := net.SplitHostPort(address)
	n, e := strconv.Atoi(port)
	return err == nil && net.ParseIP(host) != nil && e == nil && n > 0 && n <= 65535 && strconv.Itoa(n) == port
}
func probe(address, expected string) error {
	if !validAddress(address) || (expected != "allowed" && expected != "denied") {
		return errors.New("probe requires numeric address and allowed|denied")
	}
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if conn != nil {
		conn.Close()
	}
	if (err == nil) != (expected == "allowed") {
		return fmt.Errorf("TCP %s did not match %s", address, expected)
	}
	return nil
}
func run(args []string) error {
	if len(args) == 3 && args[0] == "connect" {
		return probe(args[1], args[2])
	}
	if len(args) == 2 && args[0] == "listen" && validAddress(args[1]) {
		ln, err := net.Listen("tcp", args[1])
		if err != nil {
			return err
		}
		defer ln.Close()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return err
			}
			conn.Close()
		}
	}
	return errors.New("usage: netprobe connect IP:PORT allowed|denied OR listen IP:PORT")
}
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
