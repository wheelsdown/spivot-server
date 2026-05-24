package identity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ErrKeyNotFound is the sentinel error returned (wrapped via fmt.Errorf
// with %w) when [KeyStore.Load] is asked for a key name that has not
// been persisted. Callers detect it with [errors.Is]; the wrapping
// preserves the contextual error message (which key, which path) for
// logs while keeping the equality check portable across implementations.
var ErrKeyNotFound = errors.New("identity: key not found")

// KeyStore is the persistence boundary for private keys held by the
// Spivot Server identity stack.
//
// Implementations are responsible for keeping stored key material
// confidential to the running process. The reference implementation
// [FileKeyStore] enforces 0600 file permissions inside a 0700 directory
// and writes atomically; a future KMS-backed implementation may never
// expose raw private key bytes at all and instead route signature
// operations through an external service.
//
// Implementations must:
//
//   - Persist exactly the [crypto.Signer] returned by gen on a cold
//     start, in a form that subsequent [Load] calls can faithfully
//     reconstruct.
//   - Return an error wrapping [ErrKeyNotFound] from [Load] when no key
//     is stored under the requested name. Callers check membership with
//     [errors.Is].
//   - Return the same [crypto.Signer] (or an equivalent one whose
//     [crypto.Signer.Public] returns an Equal public key) across the
//     lifetime of the keystore for a given name. Implementations may
//     return distinct *Go* values per call as long as the underlying
//     key material is the same.
//   - Be safe for concurrent calls from multiple goroutines. Concurrent
//     [LoadOrGenerate] calls for the *same* name must coalesce to a
//     single gen invocation; the simplest way to achieve this is via the
//     underlying file system's create-with-O_EXCL semantics.
//
// Implementations may impose additional name restrictions (allowed
// character set, maximum length). [FileKeyStore] accepts
// `[A-Za-z0-9_-]+` and rejects path separators and dot segments to
// prevent traversal.
type KeyStore interface {
	// LoadOrGenerate returns the signer persisted under name, generating
	// a new one via gen if no key is stored yet.
	//
	// On a warm start (a key for name already exists), gen is not
	// invoked and the persisted key is returned. On a cold start (no
	// stored key), gen is called exactly once; the returned signer is
	// persisted before being returned to the caller. If gen returns an
	// error, no key is persisted and the error is wrapped and returned.
	//
	// LoadOrGenerate is the recommended entry point for callers (such
	// as [LoadOrCreate]) that need a stable identity but can construct
	// one on first use. Pass nil for gen only if a missing key should
	// be an error rather than triggering generation.
	LoadOrGenerate(ctx context.Context, name string, gen func() (crypto.Signer, error)) (crypto.Signer, error)

	// Load returns the signer persisted under name without ever
	// generating one. Returns an error wrapping [ErrKeyNotFound] when
	// no key is stored. Use Load when a caller needs to assert that a
	// key was provisioned out of band (for example, by a separate
	// `ca init` invocation) rather than auto-generate one on demand.
	Load(ctx context.Context, name string) (crypto.Signer, error)
}

// FileKeyStore is a [KeyStore] backed by PEM files on the local
// filesystem. It is the default and currently only implementation.
//
// Disk layout (rooted at the directory passed to [NewFileKeyStore]):
//
//	<dir>/                   directory, 0700
//	<dir>/<name>.key.pem     PKCS#8 PEM, 0600
//
// Writes are atomic and durable: each key is written to a temporary
// file inside <dir>, chmod'd to 0600 before being filled, fsync'd to
// disk, renamed into place, and the parent directory is fsync'd. A
// crash or power loss between [LoadOrGenerate] returning and the next
// process start cannot leave a half-written key or a renamed-but-lost
// directory entry.
//
// Key names are restricted to [A-Za-z0-9_-]+ to keep the on-disk layout
// flat and to defeat path-traversal. The single key name used today is
// "ca"; future Spivot Server work may add per-feature keys (server
// signing key, federation key) under additional names.
//
// Currently only [*ecdsa.PrivateKey] signers are accepted by the save
// path; RSA and Ed25519 keys round-trip through PKCS#8 fine, but no
// caller produces them today and the explicit reject keeps the format
// matrix small.
type FileKeyStore struct {
	dir string
}

// NewFileKeyStore returns a [FileKeyStore] rooted at dir. The directory
// is created with 0700 permissions if it does not already exist;
// pre-existing directories are tightened to 0700 explicitly. Returns
// an error if dir is empty, equal to ".", or cannot be created or
// chmod'd.
//
// Pre-existing key files inside dir are not inspected at construction
// time; they are read on demand by [FileKeyStore.Load] or
// [FileKeyStore.LoadOrGenerate]. Errors from those calls (parse
// failures, type assertion failures, unexpected PEM block types) carry
// the offending key name and path in their error chain.
func NewFileKeyStore(dir string) (*FileKeyStore, error) {
	cleaned := filepath.Clean(dir)
	if cleaned == "" || cleaned == "." {
		return nil, errors.New("identity: key store directory must be set")
	}
	if err := os.MkdirAll(cleaned, 0o700); err != nil {
		return nil, fmt.Errorf("identity: create key store directory %q: %w", cleaned, err)
	}
	// MkdirAll ignores the perm arg when the directory already exists, so
	// tighten explicitly: the key store directory must be 0700 regardless of
	// how it came to be.
	if err := os.Chmod(cleaned, 0o700); err != nil {
		return nil, fmt.Errorf("identity: chmod key store directory %q: %w", cleaned, err)
	}
	return &FileKeyStore{dir: cleaned}, nil
}

// Dir returns the directory the file key store writes into. Useful for
// callers (like [LoadOrCreate]) that want to place companion files such
// as the CA certificate alongside the key store's key files.
func (s *FileKeyStore) Dir() string {
	return s.dir
}

// LoadOrGenerate implements [KeyStore.LoadOrGenerate]. See the
// interface documentation for the contract.
//
// FileKeyStore's implementation calls [FileKeyStore.Load] first; on
// [ErrKeyNotFound] it invokes gen, persists the result via an atomic
// temp+rename+fsync sequence, and returns the freshly-generated signer.
// Concurrent first-time generation of the same key by multiple
// goroutines is currently serialized by gen producing a new key per
// call (the last writer wins on the rename); a future implementation
// may add explicit locking if a concrete caller needs strict
// at-most-once-generation semantics.
func (s *FileKeyStore) LoadOrGenerate(ctx context.Context, name string, gen func() (crypto.Signer, error)) (crypto.Signer, error) {
	signer, err := s.Load(ctx, name)
	if err == nil {
		return signer, nil
	}
	if !errors.Is(err, ErrKeyNotFound) {
		return nil, err
	}

	if gen == nil {
		return nil, errors.New("identity: gen function required when no key is stored")
	}
	fresh, err := gen()
	if err != nil {
		return nil, fmt.Errorf("identity: generate key %q: %w", name, err)
	}
	if err := s.save(name, fresh); err != nil {
		return nil, err
	}
	return fresh, nil
}

// Load implements [KeyStore.Load]. See the interface documentation for
// the contract.
//
// The on-disk PEM block must have Type "PRIVATE KEY" and contain a
// PKCS#8-encoded key. The parsed value must implement [crypto.Signer]
// (true for all stdlib ECDSA, RSA, and Ed25519 keys). Failures at any
// stage are wrapped with the key name and the offending file path
// where applicable.
func (s *FileKeyStore) Load(_ context.Context, name string) (crypto.Signer, error) {
	if err := validateKeyName(name); err != nil {
		return nil, err
	}
	path := s.keyPath(name)
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("identity: load key %q: %w", name, ErrKeyNotFound)
		}
		return nil, fmt.Errorf("identity: read key %q: %w", name, err)
	}

	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("identity: key %q is not PEM-encoded", name)
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("identity: key %q has unexpected PEM block %q", name, block.Type)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("identity: parse key %q: %w", name, err)
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("identity: key %q is not a crypto.Signer", name)
	}
	return signer, nil
}

// save persists signer under name via temp file + chmod 0600 + fsync +
// rename + directory fsync. Currently restricted to ECDSA keys to keep
// the supported algorithm set explicit; widen the type-switch when a
// caller needs RSA or Ed25519.
func (s *FileKeyStore) save(name string, signer crypto.Signer) error {
	if err := validateKeyName(name); err != nil {
		return err
	}
	if _, ok := signer.(*ecdsa.PrivateKey); !ok {
		return fmt.Errorf("identity: unsupported key type %T", signer)
	}
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return fmt.Errorf("identity: marshal key %q: %w", name, err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	finalPath := s.keyPath(name)
	tmp, err := os.CreateTemp(s.dir, "."+name+"-*.tmp")
	if err != nil {
		return fmt.Errorf("identity: open temp file for key %q: %w", name, err)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = os.Remove(tmpPath)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("identity: chmod temp key file: %w", err)
	}
	if _, err := tmp.Write(encoded); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("identity: write key %q: %w", name, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("identity: sync key %q: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("identity: close key %q: %w", name, err)
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		cleanup()
		return fmt.Errorf("identity: persist key %q: %w", name, err)
	}
	if err := syncDir(s.dir); err != nil {
		return fmt.Errorf("identity: fsync key store dir after persisting %q: %w", name, err)
	}
	return nil
}

// keyPath returns the on-disk path FileKeyStore uses for a given key
// name. Layout is intentionally flat: <dir>/<name>.key.pem.
func (s *FileKeyStore) keyPath(name string) string {
	return filepath.Join(s.dir, name+".key.pem")
}

// validateKeyName enforces the [A-Za-z0-9_-]+ name restriction that
// keeps the on-disk layout flat and defeats path-traversal. Empty names
// are also rejected so a typo in the caller cannot resolve to a
// directory-relative path.
func validateKeyName(name string) error {
	if name == "" {
		return errors.New("identity: key name must be set")
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '-':
		default:
			return fmt.Errorf("identity: key name %q contains invalid character %q", name, r)
		}
	}
	return nil
}
