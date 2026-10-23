package agentpackage

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestVerifyRejectsTamperingAndUntrustedDetails(t *testing.T) {
	cases := map[string]func(*fixture){
		"config bytes": func(f *fixture) { f.config = []byte("[]"); f.remanifest() },
		"layer digest": func(f *fixture) { f.layer = append(f.layer, 'x') },
		"unbound instructions": func(f *fixture) {
			f.files["instructions/writer.md"] = []byte("private-prompt-payload")
			f.layer = archive(t, f.files, nil)
			f.remanifest()
		},
		"missing graph": func(f *fixture) {
			delete(f.files, "agentsuite.json")
			f.layer = archive(t, f.files, nil)
			f.remanifest()
		},
		"invalid graph JSON": func(f *fixture) {
			f.files["agentsuite.json"] = []byte(`{"private-prompt-payload": true}`)
			f.layer = archive(t, f.files, nil)
			f.remanifest()
		},
		"bad compression": func(f *fixture) { f.layer = []byte("private-prompt-payload"); f.remanifest() },
		"gzip CRC":        func(f *fixture) { f.layer[len(f.layer)-8] ^= 1; f.remanifest() },
		"concatenated gzip": func(f *fixture) {
			var b bytes.Buffer
			g := gzip.NewWriter(&b)
			g.Close()
			f.layer = append(f.layer, b.Bytes()...)
			f.remanifest()
		},
		"compressed trailing junk": func(f *fixture) { f.layer = append(f.layer, []byte("private-prompt-payload")...); f.remanifest() },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := makeFixture(t)
			mutate(&f)
			p, err := Verify(t.Context(), f.manifest, f.config, f.layer)
			if err == nil || p != nil {
				t.Fatal("accepted tampered package")
			}
			if strings.Contains(err.Error(), "private-prompt-payload") {
				t.Fatalf("leaked package data: %v", err)
			}
		})
	}
}
func TestVerifyRejectsUnsupportedManifest(t *testing.T) {
	for _, field := range []string{"subject", "artifactType", "layers", "urls", "data", "size", "digest", "unknown", "duplicate"} {
		t.Run(field, func(t *testing.T) {
			f := makeFixture(t)
			var m map[string]any
			json.Unmarshal(f.manifest, &m)
			switch field {
			case "subject":
				m[field] = map[string]any{}
			case "artifactType":
				m[field] = "container-image"
			case "layers":
				m[field] = []any{}
			case "urls", "data":
				m["config"].(map[string]any)[field] = nil
			case "size":
				m["config"].(map[string]any)[field] = -1
			case "digest":
				m["config"].(map[string]any)[field] = "sha256:abc"
			case "unknown":
				m[field] = "private-prompt-payload"
			}
			f.manifest = jsonBytes(m)
			if field == "duplicate" {
				f.manifest = append([]byte(`{"schemaVersion":2,`), f.manifest[1:]...)
			}
			if p, err := Verify(t.Context(), f.manifest, f.config, f.layer); err == nil || p != nil {
				t.Fatal("accepted unsupported manifest")
			}
		})
	}
}
func TestVerifyRejectsArchiveEntry(t *testing.T) {
	for _, name := range []string{"../escape", "/absolute", "a/../escape", "a\\escape", "instructions/writer.md", "a//b", "a/./b"} {
		t.Run(name, func(t *testing.T) {
			f := makeFixture(t)
			f.layer = archive(t, f.files, &tar.Header{Name: name, Mode: 0644, ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR})
			f.remanifest()
			if _, err := Verify(t.Context(), f.manifest, f.config, f.layer); err == nil || err.Error() != "unsupported package archive entry" {
				t.Fatalf("wrong refusal for unsafe entry: %v", err)
			}
		})
	}
	for name, kind := range map[string]byte{"symlink": tar.TypeSymlink, "hardlink": tar.TypeLink, "device": tar.TypeChar, "fifo": tar.TypeFifo} {
		t.Run(name, func(t *testing.T) {
			f := makeFixture(t)
			f.layer = archive(t, f.files, &tar.Header{Name: "extra", Linkname: "instructions/writer.md", Mode: 0644, ModTime: time.Unix(0, 0), Typeflag: kind, Format: tar.FormatUSTAR})
			f.remanifest()
			if _, err := Verify(t.Context(), f.manifest, f.config, f.layer); err == nil || err.Error() != "package links and special files are unsupported" {
				t.Fatalf("wrong special-file refusal: %v", err)
			}
		})
	}
	for _, format := range []tar.Format{tar.FormatGNU, tar.FormatPAX} {
		t.Run(format.String(), func(t *testing.T) {
			f := makeFixture(t)
			h := &tar.Header{Name: "extra", Mode: 0644, ModTime: time.Unix(0, 0), Format: format}
			if format == tar.FormatPAX {
				h.PAXRecords = map[string]string{"comment": "untrusted"}
			}
			f.layer = archive(t, f.files, h)
			f.remanifest()
			if _, err := Verify(t.Context(), f.manifest, f.config, f.layer); err == nil || err.Error() != "unsupported package archive entry" {
				t.Fatalf("wrong metadata refusal: %v", err)
			}
		})
	}
}
func TestVerifyResourceLimits(t *testing.T) {
	t.Run("manifest", func(t *testing.T) {
		f := makeFixture(t)
		f.manifest = bytes.Repeat([]byte(" "), (1<<20)+1)
		if _, err := Verify(t.Context(), f.manifest, f.config, f.layer); err == nil || err.Error() != "package exceeds byte limits" {
			t.Fatalf("wrong bound: %v", err)
		}
	})
	t.Run("compressed", func(t *testing.T) {
		f := makeFixture(t)
		f.layer = make([]byte, (8<<20)+1)
		if _, err := Verify(t.Context(), f.manifest, f.config, f.layer); err == nil || err.Error() != "package exceeds byte limits" {
			t.Fatalf("wrong bound: %v", err)
		}
	})
	t.Run("file", func(t *testing.T) {
		f := makeFixture(t)
		f.files["too-large"] = make([]byte, (1<<20)+1)
		f.layer = archive(t, f.files, nil)
		f.remanifest()
		if _, err := Verify(t.Context(), f.manifest, f.config, f.layer); err == nil || err.Error() != "unsupported package archive entry" {
			t.Fatalf("wrong file bound: %v", err)
		}
	})
	t.Run("entries", func(t *testing.T) {
		f := makeFixture(t)
		for i := 0; i < 129; i++ {
			f.files[fmt.Sprintf("extra-%03d", i)] = nil
		}
		f.layer = archive(t, f.files, nil)
		f.remanifest()
		if _, err := Verify(t.Context(), f.manifest, f.config, f.layer); err == nil || err.Error() != "unsupported package archive entry" {
			t.Fatalf("wrong entry bound: %v", err)
		}
	})
	t.Run("expanded", func(t *testing.T) {
		var b bytes.Buffer
		g := gzip.NewWriter(&b)
		tw := tar.NewWriter(g)
		for i := 0; i < 17; i++ {
			tw.WriteHeader(&tar.Header{Name: strings.Repeat("a", i+1), Mode: 0644, Size: 1 << 20, ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR})
			io.CopyN(tw, bytes.NewReader(make([]byte, 1<<20)), 1<<20)
		}
		tw.Close()
		g.Close()
		f := makeFixture(t)
		f.layer = b.Bytes()
		f.remanifest()
		if _, err := Verify(t.Context(), f.manifest, f.config, f.layer); err == nil || err.Error() != "incomplete package file" {
			t.Fatalf("wrong expansion refusal: %v", err)
		}
	})
}
func TestPullChecksTransportAndResponseIdentity(t *testing.T) {
	f := makeFixture(t)
	for _, target := range []string{"manifest", "config", "layer", "oversized", "chunked"} {
		t.Run(target, func(t *testing.T) {
			_, err := pullFixture(t, f, func(w http.ResponseWriter, r *http.Request) bool {
				switch target {
				case "manifest":
					if strings.Contains(r.URL.Path, "/manifests/") {
						w.Write([]byte("{}"))
						return true
					}
				case "config":
					if strings.HasSuffix(r.URL.Path, digest(f.config)) {
						w.Write([]byte("[]"))
						return true
					}
				case "layer":
					if strings.HasSuffix(r.URL.Path, digest(f.layer)) {
						w.Write(bytes.Repeat([]byte("x"), len(f.layer)))
						return true
					}
				case "oversized":
					w.Header().Set("Content-Length", "1048577")
					return true
				case "chunked":
					w.(http.Flusher).Flush()
					w.Write(bytes.Repeat([]byte("x"), (1<<20)+1))
					return true
				}
				return false
			})
			if err == nil {
				t.Fatal("accepted incorrect registry bytes")
			}
		})
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/test/suite/manifests/" + digest(f.manifest):
			w.Write(f.manifest)
		case "/v2/test/suite/blobs/" + digest(f.config):
			w.Write(f.config)
		case "/v2/test/suite/blobs/" + digest(f.layer):
			w.Write(f.layer)
		default:
			http.NotFound(w, r)
		}
	}))
	defer s.Close()
	host := strings.TrimPrefix(s.URL, "http://")
	repo := host + "/test/suite"
	p, _ := New(Policy{Repositories: []string{repo}}, nil)
	if _, err := p.Pull(t.Context(), repo+"@"+digest(f.manifest)); err == nil {
		t.Fatal("silently downgraded TLS")
	}
	p, err := New(Policy{Repositories: []string{repo}, HTTPRegistry: host}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Pull(t.Context(), repo+"@"+digest(f.manifest)); err != nil {
		t.Fatal(err)
	}
}
func TestPullContextAfterHeaders(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(fmt.Sprint(deadline), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			want := error(context.Canceled)
			if deadline {
				ctx, cancel = context.WithTimeout(t.Context(), 100*time.Millisecond)
				want = context.DeadlineExceeded
			}
			defer cancel()
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				if !deadline {
					timer := time.AfterFunc(25*time.Millisecond, cancel)
					defer timer.Stop()
				}
				<-r.Context().Done()
			}))
			defer s.Close()
			repo := strings.TrimPrefix(s.URL, "https://") + "/test/suite"
			p, err := New(Policy{Repositories: []string{repo}}, s.Client().Transport)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := p.Pull(ctx, repo+"@sha256:"+strings.Repeat("a", 64)); !errors.Is(err, want) {
				t.Fatalf("body read lost context identity: %v", err)
			}
		})
	}
}

// Cancel on a deterministic context observation inside extraction, rather than
// racing a timer against filesystem/decompression speed.
type extractionContext struct {
	context.Context
	cancel context.CancelFunc
	checks int
}

func (c *extractionContext) Err() error {
	c.checks--
	if c.checks == 0 {
		c.cancel()
	}
	return c.Context.Err()
}
func TestVerifyCancellationDuringExtraction(t *testing.T) {
	f := makeFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if _, err := Verify(&extractionContext{ctx, cancel, 3}, f.manifest, f.config, f.layer); !errors.Is(err, context.Canceled) {
		t.Fatalf("extraction lost cancellation: %v", err)
	}
}

func TestPolicyRejectsInvalidRepositories(t *testing.T) {
	for _, p := range []Policy{{}, {Repositories: []string{"registry.example/suite:tag"}}, {Repositories: []string{"registry.example/suite@sha256:" + strings.Repeat("a", 64)}}, {Repositories: []string{"registry.example/suite"}, HTTPRegistry: "other.example"}, {Repositories: []string{"https://registry.example/suite"}}, {Repositories: []string{"user:secret@registry.example/suite"}}, {Repositories: []string{"registry.example/a/../suite"}}} {
		if _, err := New(p, nil); err == nil {
			t.Fatalf("accepted invalid policy: %+v", p)
		}
	}
}
