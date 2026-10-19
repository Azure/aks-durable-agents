package host

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

var nativeHarnessName = regexp.MustCompile(`^bundle-v4-[0-9a-f]{64}$`)

var dnsLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func inClusterService(address string) bool {
	host, port, err := net.SplitHostPort(address)
	n, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return false
	}
	parts := strings.Split(host, ".")
	return len(parts) == 5 && dnsLabel.MatchString(parts[0]) && dnsLabel.MatchString(parts[1]) && strings.Join(parts[2:], ".") == "svc.cluster.local"
}

// Affinity prevents normal cross-node scheduling. This independent startup check
// refuses a mismatched/missing peer marker before journal migration or identity I/O.
// The operator also binds the marker's pod UID to live Kubernetes readback.
func (c Config) checkPlacement() error {
	if c.PeerNodeFile == "" && c.NodeName == "" {
		return nil
	}
	fail := errors.New("host/fixture co-location check failed: require matching peer node marker before startup; verify freshness against live pod UID separately")
	if c.PeerNodeFile == "" || c.NodeName == "" || !filepath.IsAbs(c.PeerNodeFile) || filepath.Clean(c.PeerNodeFile) != c.PeerNodeFile {
		return fail
	}
	real, err := filepath.EvalSymlinks(c.PeerNodeFile)
	if err != nil || real != c.PeerNodeFile {
		return fail
	}
	f, err := os.OpenFile(c.PeerNodeFile, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fail
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 4096 {
		return fail
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(owner.Uid) != os.Getuid() {
		return fail
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(raw) > 4096 {
		return fail
	}
	var marker struct {
		NodeName string `json:"nodeName"`
		PodUID   string `json:"podUID"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&marker) != nil || d.Decode(new(any)) != io.EOF || marker.NodeName != c.NodeName || marker.PodUID == "" {
		return fail
	}
	return nil
}
