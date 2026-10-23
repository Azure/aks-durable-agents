package agentpackage

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/agent-primitives/suite/oci"
)

// Package is an immutable snapshot of verified content, not a runnable member.
// Its zero value contains no verified artifact and cannot supply retained bytes.
type Package struct {
	digest                  string
	files                   map[string][]byte
	manifest, config, layer []byte
}

func (p *Package) Digest() string { return p.digest }

// ReadFile returns a copy from the exact tree Suite validated, never from a
// re-extraction, caller directory or retained mutable filesystem path.
func (p *Package) ReadFile(name string) ([]byte, error) {
	b, ok := p.files[name]
	if !ok || !safeName(name) {
		return nil, fs.ErrNotExist
	}
	return bytes.Clone(b), nil
}

// OCIBytes returns independent copies for durable retention. Verify must be
// called again when retained bytes are loaded; a journal alone is not a backup.
func (p *Package) OCIBytes() (manifest, config, layer []byte) {
	return bytes.Clone(p.manifest), bytes.Clone(p.config), bytes.Clone(p.layer)
}

// Verify validates copied OCI bytes without network access. The caller loading
// retained bytes must also compare Digest with the expected artifact identity.
func Verify(ctx context.Context, manifestBytes, config, layer []byte) (p *Package, err error) {
	// Preserve safe context identity even when archive/library errors are sanitized.
	defer func() {
		if cause := ctx.Err(); cause != nil {
			p, err = nil, cause
		}
	}()
	if len(manifestBytes) > maxManifest || len(config) != 2 || len(layer) > maxLayer {
		return nil, errors.New("package exceeds byte limits")
	}
	manifestBytes, config, layer = bytes.Clone(manifestBytes), bytes.Clone(config), bytes.Clone(layer)
	m, err := parseManifest(manifestBytes)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(config, []byte("{}")) || hash(config) != m.Config.Digest || int64(len(layer)) != m.Layers[0].Size || hash(layer) != m.Layers[0].Digest {
		return nil, errors.New("package blob integrity mismatch")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := os.MkdirTemp("", "ada-package-")
	if err != nil {
		return nil, errors.New("package scratch unavailable")
	}
	defer os.RemoveAll(root)
	content := filepath.Join(root, "content")
	if err := os.Mkdir(content, 0700); err != nil {
		return nil, errors.New("package scratch unavailable")
	}
	files, err := extract(ctx, content, layer)
	if err != nil {
		return nil, err
	}
	// No caller can write this private tree between validation and freezing. The
	// returned map holds precisely the bytes materialized by this extraction.
	if _, err := oci.ValidateDirectory(content); err != nil {
		return nil, errors.New("package content graph invalid")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	layout := filepath.Join(root, "layout")
	if err := os.MkdirAll(filepath.Join(layout, "blobs", "sha256"), 0700); err != nil {
		return nil, errors.New("package scratch unavailable")
	}
	writes := map[string][]byte{"oci-layout": []byte(`{"imageLayoutVersion":"1.0.0"}`), "index.json": nil}
	index := map[string]any{"schemaVersion": 2, "manifests": []any{map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": hash(manifestBytes), "size": len(manifestBytes)}}}
	writes["index.json"], err = json.Marshal(index)
	if err != nil {
		return nil, errors.New("package index invalid")
	}
	for _, blob := range [][]byte{manifestBytes, config, layer} {
		writes["blobs/sha256/"+hash(blob)[7:]] = blob
	}
	for name, b := range writes {
		if err := os.WriteFile(filepath.Join(layout, name), b, 0600); err != nil {
			return nil, errors.New("package scratch write failed")
		}
	}
	// Report only: never consume Suite's separate decompression as typed content.
	if _, err := oci.ValidatePath(layout); err != nil {
		return nil, errors.New("package OCI layout invalid")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &Package{digest: hash(manifestBytes), files: files, manifest: manifestBytes, config: config, layer: layer}, nil
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
	// Root enforces containment even if a filesystem component is replaced by a
	// symlink; lexical archive-name checks alone cannot protect that boundary.
	dir, err := os.OpenRoot(root)
	if err != nil {
		return nil, errors.New("package scratch unavailable")
	}
	defer dir.Close()
	compressed := bytes.NewReader(layer)
	gz, err := gzip.NewReader(compressed)
	if err != nil {
		return nil, errors.New("invalid package compression")
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
			return nil, errors.New("invalid package archive")
		}
		name := h.Name
		if h.Typeflag == tar.TypeDir {
			name = strings.TrimSuffix(name, "/")
		}
		if entries >= maxEntries || !safeName(name) || seen[name] || h.Size < 0 || h.Size > maxFile || h.Format != tar.FormatUSTAR || len(h.PAXRecords) > 0 || h.Mode&07000 != 0 || h.Mode&0022 != 0 {
			return nil, errors.New("unsupported package archive entry")
		}
		seen[name] = true
		dest := filepath.FromSlash(name)
		switch h.Typeflag {
		case tar.TypeDir:
			if err := dir.MkdirAll(dest, 0700); err != nil {
				return nil, errors.New("package directory invalid")
			}
		case tar.TypeReg:
			b, err := io.ReadAll(tr)
			if err != nil || int64(len(b)) != h.Size {
				return nil, errors.New("incomplete package file")
			}
			if err := dir.MkdirAll(filepath.Dir(dest), 0700); err != nil {
				return nil, errors.New("package directory invalid")
			}
			if err := dir.WriteFile(dest, b, fs.FileMode(h.Mode&0777)); err != nil {
				return nil, errors.New("package file write failed")
			}
			files[name] = b
		default:
			return nil, errors.New("package links and special files are unsupported")
		}
	}
	// Consume the gzip footer to check CRC, and reject streams hidden after tar
	// EOF, concatenated gzip members, or a decompression limit hit in metadata.
	tail, err := io.ReadAll(io.LimitReader(expanded, 1))
	if err != nil || len(tail) != 0 || expanded.N <= 0 || compressed.Len() != 0 {
		return nil, errors.New("package archive has trailing or oversized data")
	}
	return files, nil
}
