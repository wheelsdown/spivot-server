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

// ErrKeyNotFound is returned by KeyStore.Load when no key is stored under
// the requested name.
var ErrKeyNotFound = errors.New("identity: key not found")

// KeyStore persists private keys identified by a short name.
//
// Implementations must keep stored keys confidential to the running
// process. A file-backed implementation enforces 0600 permissions; a
// future HSM-backed implementation never exposes raw key material at all.
// All implementations must support concurrent reads from multiple
// goroutines once a key is loaded.
type KeyStore interface {
	// LoadOrGenerate returns the signer stored under name. If no key is
	// stored, gen is called to produce a new one, the new key is persisted,
	// and the freshly-generated signer is returned. gen is only consulted
	// on a cold start; subsequent calls return the previously-stored key.
	LoadOrGenerate(ctx context.Context, name string, gen func() (crypto.Signer, error)) (crypto.Signer, error)
	// Load returns the signer stored under name. Returns ErrKeyNotFound
	// (or an error wrapping it) when no key is stored.
	Load(ctx context.Context, name string) (crypto.Signer, error)
}

// FileKeyStore stores PEM-encoded PKCS#8 private keys under a directory
// with strict (0700 dir, 0600 file) permissions. Writes are atomic via
// temp-file-and-rename so a crash mid-write cannot leave a partially
// written key on disk.
type FileKeyStore struct {
	dir string
}

// NewFileKeyStore returns a FileKeyStore rooted at dir. The directory is
// created with 0700 permissions if it does not already exist.
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

// Dir returns the directory the file key store writes into.
func (s *FileKeyStore) Dir() string {
	return s.dir
}

// LoadOrGenerate implements KeyStore.
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

// Load implements KeyStore.
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

func (s *FileKeyStore) save(name string, signer crypto.Signer) error {
	if err := validateKeyName(name); err != nil {
		return err
	}
	if _, ok := signer.(*ecdsa.PrivateKey); !ok {
		// Currently only ECDSA keys are exercised. The marshaller below
		// accepts other algorithms (RSA, Ed25519) so this check is a
		// guard, not a hard requirement; remove or widen when a real
		// caller wants a different algorithm.
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
	return nil
}

func (s *FileKeyStore) keyPath(name string) string {
	return filepath.Join(s.dir, name+".key.pem")
}

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
