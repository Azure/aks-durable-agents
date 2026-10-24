package sessionfixture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/controller"
)

const v2Instructions = `Write plain-text release notes for the fictional Northwind Lantern v2.4 release, dated 18 October 2026. Preserve these facts: faster search and CSV export. Explicitly say this is fictional, an offline demo only, and rollout pending approval (human approval has not been granted). All source facts are invented; describe only the proposed local preview. Use the exact heading "Northwind Lantern v2.4 — 18 October 2026" and the literal phrases "offline demo only" and "rollout pending approval". Do not use the words deployed, shipped, released, live, production, publicly available, or real customer, even inside a negated disclaimer.
Return only the release notes, between 128 and 4096 UTF-8 bytes. Use no control or formatting characters except newline and tab. Do not include URLs, domains, links, markup, scripts, credentials, secrets, real customer data, or claims of actual deployment. Different valid wording is welcome; do not output a tool call. A separate approval-gated local tool handles the fictional publication.
`
const v2Marker = "{\"scenario\":\"v2\"}\n"
const v2HostVersion = "release-v2-real-model"

func validScenario(scenario string) error {
	if scenario != "v1" && scenario != "v2" {
		return errors.New("scenario must be v1 or v2")
	}
	return nil
}
func scenarioInstructions(scenario string) string {
	if scenario == "v2" {
		return v2Instructions
	}
	return FrozenInstructions
}
func newHarnessScenario(scenario string) *releaseNotesHarness {
	h := newHarness(scenarioInstructions(scenario))
	h.scenario = scenario
	return h
}

// V1 has no marker historically. V2 always has one; neither role may consume
// the other's data. Initialization never relabels a nonempty historical root.
func checkScenario(data, scenario string) error {
	if err := validScenario(scenario); err != nil {
		return err
	}
	if err := existingPrivateDirectory(data); err != nil {
		return err
	}
	path := filepath.Join(data, "scenario.json")
	raw, err := readOwnedFile(path, 1024)
	if scenario == "v1" && errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if scenario != "v2" || string(raw) != v2Marker {
		return errors.New("scenario marker mismatch; refusing mixed fixture data")
	}
	return nil
}
func initScenarioMarker(data, scenario string) error {
	if err := validScenario(scenario); err != nil {
		return err
	}
	if err := privateParent(data); err != nil {
		return err
	}
	if scenario == "v1" {
		return checkScenario(data, scenario)
	}
	if _, err := os.Lstat(filepath.Join(data, "scenario.json")); errors.Is(err, os.ErrNotExist) {
		entries, err := os.ReadDir(data)
		if err != nil {
			return err
		}
		if len(entries) != 0 {
			return errors.New("v2 requires a new empty subtree, not historical fixture data")
		}
	} else if err != nil {
		return err
	}
	if err := freezeFile(filepath.Join(data, "scenario.json"), []byte(v2Marker)); err != nil {
		return err
	}
	return checkScenario(data, scenario)
}
func readOwnedFile(path string, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("absolute private file required")
	}
	if err := existingPrivateDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !ok || int(st.Uid) != os.Getuid() || info.Size() > limit {
		return nil, errors.New("bounded owned regular mode 0600 file required")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("file bound exceeded")
	}
	return raw, nil
}

var v2Date = regexp.MustCompile(`\b18 october\s*2026\b`)
var forbiddenV2 = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://|\b(?:file|data|javascript|vbscript|mailto):|www\.|\b[a-z0-9][a-z0-9-]*\.(?:[a-z]{2,})(?:\b|/)|\b(?:\d{1,3}\.){3}\d{1,3}\b|[<>\[\]{}]|\b(?:javascript|eval|script|curl|wget|password|passwd|credential|credentials|secret|secrets|bearer|authorization|api[_ -]?key|access[_ -]?token|private[_ -]?key)\b|\b(?:sk|ghp|github_pat|AKIA)[_-][a-z0-9]+|\breal customer(?:s| data)?\b|\b(?:deployed|shipped|released|live|production|publicly available)\b)`)

func validateV2Draft(draft string) error {
	if !utf8.ValidString(draft) || len(draft) < 128 || len(draft) > 4096 {
		return errors.New("v2 draft must be 128..4096 UTF-8 bytes")
	}
	for _, r := range draft {
		if (unicode.IsControl(r) && r != '\n' && r != '\t') || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			return errors.New("v2 draft contains forbidden controls or formatting")
		}
	}
	lower := strings.ToLower(draft)
	for _, fact := range []string{"northwind lantern v2.4", "fictional", "faster search", "csv export", "offline demo only", "pending approval"} {
		if fact == "pending approval" && strings.Contains(lower, "pending human approval") {
			continue
		}
		if !strings.Contains(lower, fact) {
			return fmt.Errorf("v2 draft lacks required fact: %s", fact)
		}
	}
	if !v2Date.MatchString(lower) || forbiddenV2.MatchString(draft) {
		return errors.New("v2 draft contains forbidden content or lacks release date")
	}
	return nil
}
func validateToolScenario(scope controller.ToolCallContext, c api.ToolCall, scenario string) error {
	if scenario == bridgeScenario {
		return validateBridgeTool(scope, c)
	}
	if scenario == "" || scenario == "v1" {
		return validateTool(scope, c)
	}
	if err := validScenario(scenario); err != nil {
		return err
	}
	if !identity(scope.SessionUID, 256) || !identity(c.ID, 256) || !identity(c.IdempotencyKey, 512) || c.Mediation != api.MediationRequiresApproval {
		return errors.New("invalid tool identity or mediation")
	}
	draft, ok := c.Args["draft"].(string)
	if c.Tool != "publish_release_notes" || len(c.Args) != 2 || c.Args["destination"] != "release-notes-demo" || !ok {
		return errors.New("only the fixed fictional publication tool and destination are allowed")
	}
	return validateV2Draft(draft)
}

func harnessAddress(addr, scenario string, explicit bool) error {
	if err := validScenario(scenario); err != nil {
		return err
	}
	if scenario == "v2" && explicit && addr == "0.0.0.0:9000" {
		return nil
	}
	return loopback(addr)
}

type fixturePlacement struct {
	NodeName string `json:"nodeName"`
	PodUID   string `json:"podUID"`
}

func writePlacement(data, node, pod string) error {
	if !identity(node, 253) || !identity(pod, 256) {
		return errors.New("v2 harness requires node-name and pod-uid")
	}
	if err := checkScenario(data, "v2"); err != nil {
		return err
	}
	path := filepath.Join(data, "fixture-node.json")
	if _, err := readOwnedFile(path, 4096); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	raw, _ := json.Marshal(fixturePlacement{node, pod})
	raw = append(raw, '\n')
	f, err := os.CreateTemp(data, ".fixture-node-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(raw); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(data)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func checkPlacement(data, node string) error {
	raw, err := readOwnedFile(filepath.Join(data, "fixture-node.json"), 4096)
	if err != nil {
		return err
	}
	var p fixturePlacement
	if err = strictJSON(raw, []string{"nodeName", "podUID"}, &p); err != nil {
		return err
	}
	if p.NodeName != node || !identity(p.PodUID, 256) {
		return errors.New("fixture and host are not on the same fresh node placement")
	}
	return nil
}
func networkProbe(ctx context.Context, address, expect string, out io.Writer) error {
	return networkProbeWithDial(ctx, address, expect, out, (&net.Dialer{}).DialContext)
}

func networkProbeWithDial(ctx context.Context, address, expect string, out io.Writer, dial func(context.Context, string, string) (net.Conn, error)) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return errors.New("probe requires host:port")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return errors.New("probe requires a numeric TCP port in 1..65535")
	}
	if expect != "allowed" && expect != "denied" {
		return errors.New("probe expect must be allowed or denied")
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	conn, dialErr := dial(bounded, "tcp", address)
	allowed := dialErr == nil
	if conn != nil {
		conn.Close()
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// Only a TCP connect timeout is deny evidence. Timeout() alone also accepts
	// DNS timeouts and EAGAIN (local resource exhaustion), so check the cause.
	if dialErr != nil {
		var dns *net.DNSError
		var addr *net.AddrError
		var op *net.OpError
		timedOut := errors.Is(dialErr, context.DeadlineExceeded) || errors.Is(dialErr, os.ErrDeadlineExceeded) || errors.Is(dialErr, syscall.ETIMEDOUT)
		if errors.As(dialErr, &dns) || errors.As(dialErr, &addr) || errors.Is(dialErr, context.Canceled) ||
			!errors.As(dialErr, &op) || op.Op != "dial" || op.Net != "tcp" || !op.Timeout() || !timedOut {
			return fmt.Errorf("probe requires a TCP connection or connect timeout: %w", dialErr)
		}
	}
	if err = json.NewEncoder(out).Encode(map[string]any{"address": address, "allowed": allowed, "expect": expect, "tcpOnly": true}); err != nil {
		return err
	}
	if allowed != (expect == "allowed") {
		return errors.New("TCP connectivity did not match expectation")
	}
	return nil
}
