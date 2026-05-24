package identity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFileKeyStoreGeneratesAndReusesKey(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileKeyStore(dir)
	if err != nil {
		t.Fatalf("NewFileKeyStore: %v", err)
	}

	calls := 0
	gen := func() (crypto.Signer, error) {
		calls++
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}

	first, err := store.LoadOrGenerate(context.Background(), "ca", gen)
	if err != nil {
		t.Fatalf("first LoadOrGenerate: %v", err)
	}
	if calls != 1 {
		t.Fatalf("gen calls = %d, want 1", calls)
	}

	second, err := store.LoadOrGenerate(context.Background(), "ca", gen)
	if err != nil {
		t.Fatalf("second LoadOrGenerate: %v", err)
	}
	if calls != 1 {
		t.Fatalf("gen calls after reload = %d, want 1 (key should have been loaded)", calls)
	}

	// Public keys should match: the second call must have loaded the same
	// stored key.
	if !first.Public().(*ecdsa.PublicKey).Equal(second.Public()) {
		t.Fatal("loaded key differs from generated key")
	}
}

func TestFileKeyStoreFilePermissions(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileKeyStore(dir)
	if err != nil {
		t.Fatalf("NewFileKeyStore: %v", err)
	}

	_, err = store.LoadOrGenerate(context.Background(), "ca", func() (crypto.Signer, error) {
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	})
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("dir perms = %o, want 0700", got)
	}

	keyInfo, err := os.Stat(filepath.Join(dir, "ca.key.pem"))
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if got := keyInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("key file perms = %o, want 0600", got)
	}
}

func TestFileKeyStoreLoadMissingReturnsErrKeyNotFound(t *testing.T) {
	store, err := NewFileKeyStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileKeyStore: %v", err)
	}

	_, err = store.Load(context.Background(), "missing")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Load missing key error = %v, want ErrKeyNotFound", err)
	}
}

func TestFileKeyStoreRejectsInvalidKeyNames(t *testing.T) {
	store, err := NewFileKeyStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileKeyStore: %v", err)
	}

	cases := []string{"", "../escape", "with space", "with/slash", "weird:char"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := store.Load(context.Background(), name); err == nil {
				t.Fatal("Load() error = nil, want validation error")
			}
		})
	}
}

func TestFileKeyStoreLoadOrGenerateCoalescesConcurrentCallers(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileKeyStore(dir)
	if err != nil {
		t.Fatalf("NewFileKeyStore: %v", err)
	}

	const racers = 8
	var (
		calls atomic.Int64
		wg    sync.WaitGroup
		start sync.WaitGroup
	)
	start.Add(1)

	gen := func() (crypto.Signer, error) {
		calls.Add(1)
		// Slow the generator so multiple goroutines have time to all
		// observe ErrKeyNotFound under the racy implementation. With the
		// mutex in place, only one of them ever reaches this line.
		time.Sleep(10 * time.Millisecond)
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}

	signers := make([]crypto.Signer, racers)
	wg.Add(racers)
	for i := range racers {
		go func() {
			defer wg.Done()
			start.Wait()
			signer, err := store.LoadOrGenerate(context.Background(), "ca", gen)
			if err != nil {
				t.Errorf("racer %d LoadOrGenerate: %v", i, err)
				return
			}
			signers[i] = signer
		}()
	}
	start.Done()
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Fatalf("gen invocations = %d, want 1 (concurrent callers must coalesce)", got)
	}
	first := signers[0].Public().(*ecdsa.PublicKey)
	for i, s := range signers[1:] {
		if !first.Equal(s.Public()) {
			t.Fatalf("racer %d observed a different key than racer 0", i+1)
		}
	}
}

func TestFileKeyStoreLoadOrGenerateRequiresGen(t *testing.T) {
	store, err := NewFileKeyStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileKeyStore: %v", err)
	}

	if _, err := store.LoadOrGenerate(context.Background(), "ca", nil); err == nil {
		t.Fatal("LoadOrGenerate(nil gen) error = nil, want error")
	}
}

func TestNewFileKeyStoreRejectsEmptyDir(t *testing.T) {
	if _, err := NewFileKeyStore(""); err == nil {
		t.Fatal("NewFileKeyStore(\"\") error = nil, want error")
	}
}
