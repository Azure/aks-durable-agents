package agentcontroller

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Azure/aks-durable-agents/internal/agentpackage"
	"github.com/agent-primitives/sessions/controller"
	"github.com/gowebpki/jcs"
	"k8s.io/apimachinery/pkg/util/validation"
	"oras.land/oras-go/v2/registry"
)

// RunnerABI changes whenever packaged execution or frozen configuration semantics change.
const RunnerABI = "ada-agent-chat-v1"

var errRetained = errors.New("agentcontroller: incompatible retained definition")

type definition struct {
	Namespace, Name, UID string
	Generation           int64
	Spec                 Spec
	Binding              []byte
	Revision, Harness    string
	ABI, Model           string
}
type cachedPackage struct{ Manifest, Config, Layer []byte }

// retained is confined to one lifecycle goroutine. Model callbacks are immutable;
// stop/join the controller and close its SDK registry before closing this manager.
type retained struct {
	definitions     map[string]definition
	config          Config
	binding         json.RawMessage
	root, sockets   *os.Root
	lock            *os.File
	socketDirectory string
	servers         map[string]*ownedServer
	model           controller.ModelFunc
	stream          controller.StreamFunc
}

func retainedHash(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}
func retainedJSON(v any) []byte { b, _ := json.Marshal(v); return b }
func (d definition) identity() (string, string) {
	revision := retainedHash(retainedJSON(struct{ Package, Member, Binding, Model, ABI string }{retainedReferenceDigest(d.Spec.Package.Reference), d.Spec.Member, retainedHash(d.Binding), d.Model, d.ABI}))
	h := sha256.Sum256(retainedJSON(struct {
		Namespace, Name, UID string
		Generation           int64
		Revision             string
	}{d.Namespace, d.Name, d.UID, d.Generation, revision}))
	return revision, "a-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h[:]))
}
func retainedReferenceDigest(ref string) string {
	r, err := registry.ParseReference(ref)
	_, digest, ok := strings.Cut(ref, "@")
	if err != nil || !ok || r.Reference != digest || !strings.HasPrefix(digest, "sha256:") {
		return ""
	}
	return digest
}
func (r *retained) validate(d definition) error {
	binding, err := jcs.Transform(d.Binding)
	revision, name := d.identity()
	if err != nil || !bytes.Equal(binding, d.Binding) || len(binding) == 0 || binding[0] != '{' || d.ABI != RunnerABI || d.Model == "" || d.Namespace != r.config.Namespace || len(validation.IsDNS1123Label(d.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(d.Name)) != 0 || d.UID == "" || d.Generation < 1 || d.Spec.ModelBindingRef.Name != "default" || d.Spec.Member == "" || retainedReferenceDigest(d.Spec.Package.Reference) == "" || d.Revision != revision || d.Harness != name {
		return errRetained
	}
	return nil
}

func openRetained(c Config, model controller.ModelFunc, stream controller.StreamFunc) (_ *retained, err error) {
	binding, err := jcs.Transform(c.Binding)
	if err != nil || len(binding) == 0 || binding[0] != '{' || len(binding) > 64<<10 || c.Model == "" || c.Puller == nil {
		return nil, errRetained
	}
	absolute, err := filepath.Abs(c.Directory)
	if err != nil || c.Directory == "" {
		return nil, errRetained
	}
	r := &retained{config: c, binding: binding, definitions: map[string]definition{}, servers: map[string]*ownedServer{}, model: model, stream: stream}
	defer func() {
		if err != nil {
			r.close()
		}
	}()
	if r.root, err = privateRoot(absolute); err != nil {
		return nil, err
	}
	r.socketDirectory = filepath.Join("/tmp", "ada-agent-"+retainedHash([]byte(absolute))[7:23])
	if r.sockets, err = privateRoot(r.socketDirectory); err != nil {
		return nil, err
	}
	if r.lock, err = r.root.OpenFile("manager.lock", os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600); err != nil {
		return nil, err
	}
	info, err := r.lock.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		return nil, errRetained
	}
	if err = syscall.Flock(int(r.lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, err
	}
	dir, err := r.root.Open(".")
	if err != nil {
		return nil, err
	}
	entries, err := dir.ReadDir(-1)
	_ = dir.Close()
	if err != nil {
		return nil, err
	}
	if err = recoverRetained(r.root, entries); err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "d-") {
			continue
		}
		var d definition
		if err = readRetained(r.root, entry.Name(), 128<<10, &d); err != nil {
			return nil, err
		}
		if err = r.validate(d); err != nil {
			return nil, err
		}
		if entry.Name() != "d-"+d.Harness+".json" {
			return nil, errRetained
		}
		var cached cachedPackage
		if err = readRetained(r.root, "p-"+retainedReferenceDigest(d.Spec.Package.Reference)[7:]+".json", 16<<20, &cached); err != nil {
			return nil, err
		}
		p, e := agentpackage.Verify(context.Background(), retainedReferenceDigest(d.Spec.Package.Reference), cached.Manifest, cached.Config, cached.Layer)
		if e != nil {
			return nil, e
		}
		r.definitions[d.Harness] = d
		if err = r.serve(d, p); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func (r *retained) remember(ctx context.Context, a Agent, p *agentpackage.Package) (definition, error) {
	if err := r.config.Puller.ValidateReference(a.Spec.Package.Reference); err != nil {
		return definition{}, err
	}
	d := definition{Namespace: a.Namespace, Name: a.Name, UID: string(a.UID), Generation: a.Generation, Spec: a.Spec, Binding: bytes.Clone(r.binding), ABI: RunnerABI, Model: r.config.Model}
	d.Revision, d.Harness = d.identity()
	if err := r.validate(d); err != nil {
		return d, err
	}
	if p == nil || p.Digest() != retainedReferenceDigest(d.Spec.Package.Reference) {
		return d, errRetained
	}
	if _, err := packagedHarness(p, d); err != nil {
		return d, err
	}
	for _, old := range r.definitions {
		if old.Namespace == d.Namespace && old.Name == d.Name && old.UID == d.UID && old.Generation == d.Generation && !bytes.Equal(retainedJSON(old), retainedJSON(d)) {
			return d, errRetained
		}
	}
	if err := ctx.Err(); err != nil {
		return d, err
	}
	m, c, l := p.OCIBytes()
	if err := publishRetained(r.root, "p-"+p.Digest()[7:]+".json", retainedJSON(cachedPackage{m, c, l}), 16<<20); err != nil {
		return d, err
	}
	if err := publishRetained(r.root, "d-"+d.Harness+".json", retainedJSON(d), 128<<10); err != nil {
		return d, err
	}
	r.definitions[d.Harness] = d
	return d, r.serve(d, p)
}

func privateRoot(path string) (*os.Root, error) {
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 || int(info.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() {
		return nil, errRetained
	}
	r, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	opened, err := r.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		r.Close()
		return nil, errRetained
	}
	return r, nil
}

// A link-before-unlink crash can leave exactly two aliases inside this root.
// Remove only the proven temporary alias; outside hard links remain rejected.
func recoverRetained(root *os.Root, entries []os.DirEntry) error {
	published := map[[2]uint64]bool{}
	temporary := map[string][2]uint64{}
	for _, entry := range entries {
		info, err := root.Lstat(entry.Name())
		if err != nil {
			return err
		}
		st := info.Sys().(*syscall.Stat_t)
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || int(st.Uid) != os.Geteuid() || st.Nlink != 2 {
			continue
		}
		key := [2]uint64{uint64(st.Dev), uint64(st.Ino)}
		if strings.HasPrefix(entry.Name(), "d-") || strings.HasPrefix(entry.Name(), "p-") {
			published[key] = true
		} else if strings.HasPrefix(entry.Name(), ".tmp-") {
			temporary[entry.Name()] = key
		}
	}
	for name, key := range temporary {
		if published[key] {
			if err := root.Remove(name); err != nil {
				return err
			}
		}
	}
	return nil
}
func privateFile(info os.FileInfo) bool {
	st := info.Sys().(*syscall.Stat_t)
	return info.Mode().IsRegular() && info.Mode().Perm()&0077 == 0 && int(st.Uid) == os.Geteuid() && st.Nlink == 1
}
func retainedBytes(root *os.Root, name string, limit int64) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !privateFile(info) || info.Size() > limit {
		return nil, errRetained
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) || !privateFile(opened) {
		return nil, errRetained
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errRetained
	}
	return b, nil
}
func readRetained(root *os.Root, name string, limit int64, out any) error {
	b, err := retainedBytes(root, name, limit)
	if err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return errRetained
	}
	return nil
}

// Publish with a hard link, not rename: an occupied key must never be overwritten.
func publishRetained(root *os.Root, name string, b []byte, limit int64) error {
	if int64(len(b)) > limit {
		return errRetained
	}
	tmp := ".tmp-" + rand.Text()
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(tmp)
	defer f.Close()
	if _, err = f.Write(b); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = root.Link(tmp, name); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		existing, e := retainedBytes(root, name, limit)
		if e != nil {
			return e
		}
		if !bytes.Equal(existing, b) {
			return errRetained
		}
	}
	if err = root.Remove(tmp); err != nil {
		return err
	}
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (r *retained) close() {
	for name, server := range r.servers {
		server.close()
		delete(r.servers, name)
	}
	for _, c := range []io.Closer{r.lock, r.sockets, r.root} {
		switch v := c.(type) {
		case *os.File:
			if v != nil {
				_ = v.Close()
			}
		case *os.Root:
			if v != nil {
				_ = v.Close()
			}
		}
	}
}
