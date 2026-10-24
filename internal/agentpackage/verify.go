package agentpackage

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/agent-primitives/suite/core"
	"github.com/agent-primitives/suite/oci"
)

// Package is an immutable snapshot of verified content, not a runnable member.
// Its zero value contains no verified artifact or report.
type Package struct {
	digest                  string
	files                   map[string][]byte
	manifest, config, layer []byte
	report                  *core.Report
}

func (p *Package) Digest() string { return p.digest }

// ReadFile returns copied bytes from the exact tree Suite validated.
func (p *Package) ReadFile(name string) ([]byte, error) {
	b, ok := p.files[name]
	if !ok || !safeName(name) {
		return nil, fs.ErrNotExist
	}
	return bytes.Clone(b), nil
}

// OCIBytes returns independent copies for durable retention and re-verification.
func (p *Package) OCIBytes() (manifest, config, layer []byte) {
	return bytes.Clone(p.manifest), bytes.Clone(p.config), bytes.Clone(p.layer)
}

// Report returns an independent snapshot, including nested platform collections.
func (p *Package) Report() *core.Report {
	if p.report == nil {
		return nil
	}
	r := *p.report
	r.Capabilities = slices.Clone(r.Capabilities)
	r.AgentPlatforms = slices.Clone(r.AgentPlatforms)
	r.CompositionSelections = slices.Clone(r.CompositionSelections)
	for i := range r.AgentPlatforms {
		r.AgentPlatforms[i].Platforms = slices.Clone(r.AgentPlatforms[i].Platforms)
	}
	return &r
}

// Verify checks copied bytes against the required manifest identity before any
// parsing or extraction. It performs no network access or runnable-profile check.
func Verify(ctx context.Context, expectedDigest string, manifestBytes, config, layer []byte) (p *Package, err error) {
	defer func() {
		if ctx.Err() != nil {
			p, err = nil, cancellation(ctx, "package")
		}
	}()
	if !validDigest(expectedDigest) {
		return nil, fault(ErrUnsupported, "manifest", "digest-reference")
	}
	if len(manifestBytes) > maxManifest || len(config) != 2 || len(layer) > maxLayer {
		return nil, fault(ErrUnsupported, "package", "byte-limits")
	}
	manifestBytes, config, layer = bytes.Clone(manifestBytes), bytes.Clone(config), bytes.Clone(layer)
	if hash(manifestBytes) != expectedDigest {
		return nil, fault(ErrIntegrity, "manifest", "expected-digest")
	}
	m, err := parseManifest(manifestBytes)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(config, []byte("{}")) || hash(config) != m.Config.Digest {
		return nil, fault(ErrIntegrity, "config", "descriptor-body")
	}
	if int64(len(layer)) != m.Layers[0].Size || hash(layer) != m.Layers[0].Digest {
		return nil, fault(ErrIntegrity, "layer", "descriptor-body")
	}
	if ctx.Err() != nil {
		return nil, cancellation(ctx, "package")
	}
	root, err := os.MkdirTemp("", "ada-package-")
	if err != nil {
		return nil, fault(ErrUnavailable, "package", "scratch-create")
	}
	defer os.RemoveAll(root)
	content := filepath.Join(root, "content")
	if err := os.Mkdir(content, 0700); err != nil {
		return nil, fault(ErrUnavailable, "package", "scratch-create")
	}
	files, err := extract(ctx, content, layer)
	if err != nil {
		return nil, err
	}
	// Typed content and the report come only from this single private extraction.
	report, err := oci.ValidateDirectory(content)
	if err != nil {
		return nil, fault(ErrIntegrity, "content", "suite-graph")
	}
	if ctx.Err() != nil {
		return nil, cancellation(ctx, "package")
	}
	layout := filepath.Join(root, "layout")
	if err := os.MkdirAll(filepath.Join(layout, "blobs", "sha256"), 0700); err != nil {
		return nil, fault(ErrUnavailable, "package", "scratch-create")
	}
	writes := map[string][]byte{"oci-layout": []byte(`{"imageLayoutVersion":"1.0.0"}`), "index.json": nil}
	index := map[string]any{"schemaVersion": 2, "manifests": []any{map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": expectedDigest, "size": len(manifestBytes)}}}
	writes["index.json"], err = json.Marshal(index)
	if err != nil {
		return nil, fault(ErrIntegrity, "manifest", "layout-index")
	}
	for _, blob := range [][]byte{manifestBytes, config, layer} {
		writes["blobs/sha256/"+hash(blob)[7:]] = blob
	}
	for name, b := range writes {
		if err := os.WriteFile(filepath.Join(layout, name), b, 0600); err != nil {
			return nil, fault(ErrUnavailable, "package", "scratch-write")
		}
	}
	// Envelope validation only; never use a second extraction as typed content.
	if _, err := oci.ValidatePath(layout); err != nil {
		return nil, fault(ErrIntegrity, "manifest", "suite-layout")
	}
	return &Package{digest: expectedDigest, files: files, manifest: manifestBytes, config: config, layer: layer, report: report}, nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(b)
}
func safeName(name string) bool {
	return fs.ValidPath(name) && name != "." && path.Clean(name) == name && !strings.Contains(name, "\\") && utf8.ValidString(name)
}
func extract(ctx context.Context, root string, layer []byte) (map[string][]byte, error) {
	// Root enforces containment even if an existing component becomes a symlink.
	dir, err := os.OpenRoot(root)
	if err != nil {
		return nil, fault(ErrUnavailable, "archive", "scratch-open")
	}
	defer dir.Close()
	compressed := bytes.NewReader(layer)
	gz, err := gzip.NewReader(compressed)
	if err != nil {
		return nil, fault(ErrIntegrity, "archive", "gzip")
	}
	defer gz.Close()
	gz.Multistream(false)
	expanded := &io.LimitedReader{R: contextReader{ctx, gz}, N: maxExpanded + 1}
	tr := tar.NewReader(expanded)
	files := map[string][]byte{}
	seen := map[string]bool{}
	for entries := 0; ; entries++ {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fault(ErrIntegrity, "archive", "tar")
		}
		name := h.Name
		if h.Typeflag == tar.TypeDir {
			name = strings.TrimSuffix(name, "/")
		}
		switch {
		case entries >= maxEntries:
			return nil, fault(ErrUnsupported, "archive", "entry-count")
		case !safeName(name):
			return nil, fault(ErrUnsupported, "archive", "entry-path")
		case seen[name]:
			return nil, fault(ErrUnsupported, "archive", "duplicate-path")
		case h.Size < 0 || h.Size > maxFile:
			return nil, fault(ErrUnsupported, "archive", "file-size")
		case h.Format != tar.FormatUSTAR || len(h.PAXRecords) > 0:
			return nil, fault(ErrUnsupported, "archive", "tar-format")
		case h.Mode&07000 != 0 || h.Mode&0022 != 0:
			return nil, fault(ErrUnsupported, "archive", "entry-mode")
		}
		seen[name] = true
		dest := filepath.FromSlash(name)
		switch h.Typeflag {
		case tar.TypeDir:
			if err := dir.MkdirAll(dest, 0700); err != nil {
				return nil, fault(ErrUnavailable, "archive", "directory-write")
			}
		case tar.TypeReg:
			b, err := io.ReadAll(tr)
			if err != nil || int64(len(b)) != h.Size {
				return nil, fault(ErrIntegrity, "archive", "file-body")
			}
			if err := dir.MkdirAll(filepath.Dir(dest), 0700); err != nil {
				return nil, fault(ErrUnavailable, "archive", "directory-write")
			}
			if err := dir.WriteFile(dest, b, fs.FileMode(h.Mode&0777)); err != nil {
				return nil, fault(ErrUnavailable, "archive", "file-write")
			}
			files[name] = b
		default:
			return nil, fault(ErrUnsupported, "archive", "entry-type")
		}
	}
	// Check footer/CRC, trailing content, concatenated gzip and decompression cap.
	tail, err := io.ReadAll(io.LimitReader(expanded, 1))
	if err != nil || len(tail) != 0 || expanded.N <= 0 || compressed.Len() != 0 {
		return nil, fault(ErrIntegrity, "archive", "archive-tail")
	}
	return files, nil
}
