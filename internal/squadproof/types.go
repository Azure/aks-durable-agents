// Package squadproof contains unwired, synthetic fixtures for a local team proof.
// It is not a production coordinator, journal verifier or authorization service.
package squadproof

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
)

var (
	ErrInvalid  = errors.New("proof: invalid input")
	ErrConflict = errors.New("proof: immutable identity conflict")
	ErrHeld     = errors.New("proof: operation held")
	ErrNotFound = errors.New("proof: not found")
	ErrForeign  = errors.New("proof: foreign or unsupported ledger")
)

// Operation holds immutable admission plus host-owned session and execution evidence.
// Only trusted host setup calls Admit/BindSession; tools cannot create lead authority.
type Operation struct {
	ID, Kind, ParentID, SessionUID, Team, PackageDigest, Member string
	Payload                                                     json.RawMessage
	PayloadHash                                                 string
	Epoch, InputHeadSeq                                         int64
	State                                                       string
	Evidence                                                    Evidence
	Reason                                                      string
}

type Input struct {
	ID, Target, Kind, Source, TerminalHash string
	Payload                                json.RawMessage
	PayloadHash                            string
	Ordinal, Epoch, HeadSeq                int64
	State, ExecutionID                     string
}

// Evidence must come from the trusted journal scanner, not a model/tool argument.
// The ledger checks correlation/order but does not verify a Sessions hash chain.
type Evidence struct {
	ExecutionID                                          string
	RequestSeq, DecisionSeq, ReceiptSeq, EndSeq, HeadSeq int64
	HeadHash, EndHash                                    string
}

type Stats struct{ Operations, Inputs, ToolResults, Effects, Events int }

func identity(s string) bool {
	return s != "" && len(s) <= 256 && utf8.ValidString(s) && strings.TrimSpace(s) == s && strings.IndexFunc(s, unicode.IsControl) < 0
}
func digest(s string) bool {
	if len(s) != 2*sha256.Size {
		return false
	}
	raw, err := hex.DecodeString(s)
	return err == nil && len(raw) == sha256.Size && strings.ToLower(s) == s
}
func canonical(raw []byte) ([]byte, string, error) {
	if len(raw) == 0 || len(raw) > 16<<10 {
		return nil, "", ErrInvalid
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil {
		return nil, "", ErrInvalid
	}
	out, err := jcs.Transform(raw)
	if err != nil {
		return nil, "", ErrInvalid
	}
	hash := sha256.Sum256(out)
	return out, hex.EncodeToString(hash[:]), nil
}
func (e Evidence) valid() bool {
	if !identity(e.ExecutionID) || !digest(e.HeadHash) || e.HeadSeq <= 0 {
		return false
	}
	for _, n := range []int64{e.RequestSeq, e.DecisionSeq, e.ReceiptSeq, e.EndSeq} {
		if n < 0 || n > e.HeadSeq {
			return false
		}
	}
	if e.RequestSeq == 0 && (e.DecisionSeq != 0 || e.ReceiptSeq != 0) {
		return false
	}
	if e.DecisionSeq != 0 && e.DecisionSeq <= e.RequestSeq {
		return false
	}
	if e.ReceiptSeq != 0 && (e.DecisionSeq == 0 || e.ReceiptSeq <= e.DecisionSeq) {
		return false
	}
	if e.EndSeq == 0 {
		return e.EndHash == ""
	}
	return digest(e.EndHash) && (e.RequestSeq == 0 || (e.ReceiptSeq > 0 && e.EndSeq > e.ReceiptSeq)) && (e.EndSeq != e.HeadSeq || e.EndHash == e.HeadHash)
}
