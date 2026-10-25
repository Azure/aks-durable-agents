package qualification

import (
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A printable '<' is a valid ID byte but occupies six bytes in json.Marshal.
// Catches reserving only ASCII length rather than the worst request wire size.
func TestValidatePlanReservesWorstCaseEncodedRequestIdentity(t *testing.T) {
	p := testPlan()
	p.Cases[0].Assertions = nil
	for i := 0; i < 128; i++ {
		p.Cases[0].Assertions = append(p.Cases[0].Assertions, Assertion{ID: strconv.Itoa(i), Kind: "contains", Value: strings.Repeat("x", 3900)})
	}
	ordinary := Request{Key: strings.Repeat("p", 128), Requester: strings.Repeat("p", 128), Plan: p}
	encoded, err := json.Marshal(ordinary)
	if err != nil {
		t.Fatal(err)
	}
	remaining := maxRequestBytes - len(encoded)
	for i := range p.Cases[0].Assertions {
		a := &p.Cases[0].Assertions[i]
		n := min(4096-len(a.Value), remaining)
		a.Value += strings.Repeat("x", n)
		remaining -= n
	}
	if remaining != 0 || validateRequest(ordinary) != nil {
		t.Fatal("ordinary identity boundary fixture invalid")
	}
	worst := Request{Key: strings.Repeat("<", 128), Requester: strings.Repeat("<", 128), Plan: p}
	if !errors.Is(validateRequest(worst), ErrInvalid) {
		t.Fatal("escaped identity did not cross metadata bound")
	}
	if !errors.Is(ValidatePlan(p), ErrInvalid) {
		t.Fatal("plan accepted without room for maximally escaped request identities")
	}
	p.Cases[0].Assertions[0].Value = p.Cases[0].Assertions[0].Value[1280:]
	encoded, err = json.Marshal(worst)
	if err != nil || len(encoded) != maxRequestBytes || validateRequest(worst) != nil || ValidatePlan(p) != nil {
		t.Fatalf("exact worst-case request bound refused: bytes=%d err=%v", len(encoded), err)
	}
}

// Catches a preparation validator accepting plans the existing request validator refuses.
func TestValidatePlanReusesAdmissionBoundsWithoutMutation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Plan)
	}{
		{"valid", func(*Plan) {}},
		{"workspace", func(p *Plan) { p.Subject.Workspace = "bad\nworkspace" }},
		{"digest", func(p *Plan) { p.IndexDigest = "sha256:bad" }},
		{"expiry", func(p *Plan) { p.ExpiresAt = time.Time{} }},
		{"slots", func(p *Plan) { p.Cases[0].Runs, p.Cases[0].MinPasses = 65, 1 }},
		{"tool operand", func(p *Plan) {
			p.Cases[0].Assertions[0] = Assertion{ID: "tool", Kind: "toolNotCalled", Value: "送信"}
		}},
		{"value bytes", func(p *Plan) { p.Cases[0].Assertions[0].Value = strings.Repeat("a", 4097) }},
		{"rows", func(p *Plan) {
			p.Cases[0].Runs = 64
			p.Cases[0].Assertions = nil
			for i := 0; i < 501; i++ {
				p.Cases[0].Assertions = append(p.Cases[0].Assertions, Assertion{ID: strconv.Itoa(i), Kind: "contains", Value: "x"})
			}
		}},
		{"metadata", func(p *Plan) {
			p.Cases[0].Assertions = nil
			for i := 0; i < 128; i++ {
				p.Cases[0].Assertions = append(p.Cases[0].Assertions, Assertion{ID: string(rune(33+i/94)) + string(rune(33+i%94)), Kind: "contains", Value: strings.Repeat("a", 4096)})
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := testPlan()
			tc.change(&p)
			before := objectDigest("test", p)
			want := validateRequest(Request{Key: strings.Repeat("<", 128), Requester: strings.Repeat("<", 128), Plan: p})
			got := ValidatePlan(p)
			if !errors.Is(got, want) || !reflect.DeepEqual(before, objectDigest("test", p)) {
				t.Fatalf("validation parity/mutation: got %v want %v", got, want)
			}
			if tc.name != "valid" && !errors.Is(got, ErrInvalid) {
				t.Fatal("invalid fixture accepted")
			}
		})
	}
}
