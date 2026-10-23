package sessionfixture

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"unicode/utf8"
)

const agentFileParserCommit = "bc1fc4a7c0ebeac37ef340c7928ed80e844f7643"
const agentFileProjectionLimit = 1 << 20
const agentFileMarker = "{\"scenario\":\"agent-file-v1\"}\n"

// This is an operator-trusted projection from the pinned canonical parser, not
// a second Markdown validator or proof that any example ran or passed.
type agentFileProjection struct {
	Version            int             `json:"version"`
	ParserCommit       string          `json:"parser_commit"`
	Source             []byte          `json:"source"`
	SourceSHA256       string          `json:"source_sha256"`
	AgentID            string          `json:"agent_id"`
	AuthoredModel      string          `json:"authored_model"`
	Instructions       string          `json:"instructions"`
	InstructionsSHA256 string          `json:"instructions_sha256"`
	Examples           json.RawMessage `json:"examples"`
	ExamplesSHA256     string          `json:"examples_sha256"`
}

type agentFileProfile struct {
	Version int `json:"version"`
	// Base64 preserves the exact input JSON, including whitespace inside Examples.
	Projection     []byte `json:"projection"`
	TargetModel    string `json:"target_model"`
	ProofKind      string `json:"proof_kind"`
	TargetExamples string `json:"target_examples"`
}

type agentFileSummary struct {
	Route              string `json:"route"`
	ProfileSHA256      string `json:"profile_sha256"`
	ParserCommit       string `json:"parser_commit"`
	SourceSHA256       string `json:"source_sha256"`
	InstructionsSHA256 string `json:"instructions_sha256"`
	ExamplesSHA256     string `json:"examples_sha256"`
	AuthoredModel      string `json:"authored_model"`
	TargetModel        string `json:"target_model"`
	ProofKind          string `json:"proof_kind"`
	TargetExamples     string `json:"target_examples"`
}

func agentFileDigest(raw []byte) string { return "sha256:" + digestBytes(raw) }

var agentFileModel = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)

func validAgentFileModel(model string) bool {
	return agentFileModel.MatchString(model) && !strings.EqualFold(model, "auto") && !strings.Contains(model, "://")
}

func decodeAgentFileProjection(raw []byte) (p agentFileProjection, err error) {
	refused := errors.New("agent-file projection refused: check version, parser pin, bounds and hashes")
	if len(raw) > agentFileProjectionLimit || strictJSON(raw, []string{"version", "parser_commit", "source", "source_sha256", "agent_id", "authored_model", "instructions", "instructions_sha256", "examples", "examples_sha256"}, &p) != nil {
		return agentFileProjection{}, refused
	}
	if p.Version != 1 || p.ParserCommit != agentFileParserCommit || p.AgentID != "release-writer" || !validAgentFileModel(p.AuthoredModel) || len(p.Source) == 0 || len(p.Source) > 256*1024 || !utf8.Valid(p.Source) || !utf8.ValidString(p.Instructions) || strings.TrimSpace(p.Instructions) == "" || p.SourceSHA256 != agentFileDigest(p.Source) || p.InstructionsSHA256 != agentFileDigest([]byte(p.Instructions)) || p.ExamplesSHA256 != agentFileDigest(p.Examples) {
		return agentFileProjection{}, refused
	}
	// Parse at the pin normalizes CRLF and includes all lines before Examples,
	// with one trailing LF. Check that byte relationship, not the authoring grammar.
	normalized := bytes.ReplaceAll(p.Source, []byte("\r\n"), []byte("\n"))
	instructions := []byte(p.Instructions)
	if !bytes.HasPrefix(normalized, instructions) || !bytes.HasPrefix(normalized[len(instructions):], []byte("## Examples\n")) {
		return agentFileProjection{}, refused
	}
	var examples []json.RawMessage
	if json.Unmarshal(p.Examples, &examples) != nil || len(examples) == 0 || len(examples) > 128 {
		return agentFileProjection{}, refused
	}
	return p, nil
}

// existingPrivateDirectory checks location and mode, but not UID. This boundary
// also requires ownership, without creating directories or repairing permissions.
func agentFileDirectory(data string) error {
	if existingPrivateDirectory(data) != nil {
		return errors.New("agent-file requires an existing owned private directory")
	}
	info, err := os.Stat(data)
	if err != nil {
		return errors.New("agent-file directory inspection failed")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Getuid() {
		return errors.New("agent-file directory must be owned by the current user")
	}
	return nil
}

func prepareAgentFile(data, projectionPath, targetModel string) (agentFileSummary, error) {
	var zero agentFileSummary
	if err := agentFileDirectory(data); err != nil {
		return zero, err
	}
	if agentFileDirectory(filepath.Dir(projectionPath)) != nil {
		return zero, errors.New("agent-file projection requires an absolute private file")
	}
	raw, err := readOwnedFile(projectionPath, agentFileProjectionLimit)
	if err != nil {
		return zero, errors.New("agent-file projection read refused")
	}
	p, err := decodeAgentFileProjection(raw)
	if err != nil {
		return zero, err
	}
	if !validAgentFileModel(targetModel) || targetModel == p.AuthoredModel {
		return zero, errors.New("agent-file requires an explicit different target model")
	}
	dir, err := os.Open(data)
	if err != nil {
		return zero, errors.New("agent-file data directory open failed")
	}
	defer dir.Close()
	// Read at most one name: an operator-selected directory can be arbitrarily large.
	if _, err = dir.Readdirnames(1); err != io.EOF {
		return zero, errors.New("agent-file preparation requires a new empty directory")
	}
	profile := agentFileProfile{Version: 1, Projection: raw, TargetModel: targetModel, ProofKind: "different-model-source-file", TargetExamples: "not-run"}
	frozen, err := json.Marshal(profile)
	if err != nil {
		return zero, errors.New("agent-file profile encoding failed")
	}
	frozen = append(frozen, '\n')
	// A failure leaves partial state for reconciliation. Never retry, remove,
	// overwrite or accept an identical pre-existing profile/marker as preparation.
	for _, file := range []struct {
		name string
		raw  []byte
	}{{"scenario.json", []byte(agentFileMarker)}, {"agent-file.json", frozen}} {
		if err := writeAgentFileOnce(filepath.Join(data, file.name), file.raw); err != nil {
			return zero, err
		}
	}
	_, summary, err := loadAgentFile(data)
	return summary, err
}

func writeAgentFileOnce(path string, raw []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return errors.New("agent-file create refused; reconcile retained state before a new preparation")
	}
	defer f.Close()
	if _, err = f.Write(raw); err != nil {
		return errors.New("agent-file write failed; reconcile partial state")
	}
	if err = f.Sync(); err != nil {
		return errors.New("agent-file file sync failed; reconcile partial state")
	}
	if err = f.Close(); err != nil {
		return errors.New("agent-file close failed; reconcile partial state")
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return errors.New("agent-file directory sync open failed; reconcile partial state")
	}
	defer dir.Close()
	if err = dir.Sync(); err != nil {
		return errors.New("agent-file directory sync failed; reconcile partial state")
	}
	return nil
}

func loadAgentFile(data string) (agentFileProfile, agentFileSummary, error) {
	var profile agentFileProfile
	var zero agentFileSummary
	fail := func() (agentFileProfile, agentFileSummary, error) {
		return agentFileProfile{}, zero, errors.New("agent-file profile read or integrity check refused")
	}
	if err := agentFileDirectory(data); err != nil {
		return agentFileProfile{}, zero, err
	}
	marker, err := readOwnedFile(filepath.Join(data, "scenario.json"), 1024)
	if err != nil || string(marker) != agentFileMarker {
		return fail()
	}
	// The frozen envelope base64-encodes up to 1 MiB of projection JSON.
	raw, err := readOwnedFile(filepath.Join(data, "agent-file.json"), 2<<20)
	if err != nil || strictJSON(raw, []string{"version", "projection", "target_model", "proof_kind", "target_examples"}, &profile) != nil || profile.Version != 1 || profile.ProofKind != "different-model-source-file" || profile.TargetExamples != "not-run" || !validAgentFileModel(profile.TargetModel) {
		return fail()
	}
	p, err := decodeAgentFileProjection(profile.Projection)
	if err != nil || profile.TargetModel == p.AuthoredModel {
		return fail()
	}
	summary := agentFileSummary{Route: "release-writer-file-v1-" + digestBytes(raw), ProfileSHA256: agentFileDigest(raw), ParserCommit: p.ParserCommit, SourceSHA256: p.SourceSHA256, InstructionsSHA256: p.InstructionsSHA256, ExamplesSHA256: p.ExamplesSHA256, AuthoredModel: p.AuthoredModel, TargetModel: profile.TargetModel, ProofKind: profile.ProofKind, TargetExamples: profile.TargetExamples}
	return profile, summary, nil
}
