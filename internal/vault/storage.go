package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/torquemada163/tui-ssh-manager/internal/domain"
	"golang.org/x/sys/unix"
)

type Store struct {
	mu   sync.Mutex
	Path string
	h    header
	key  []byte
	base domain.Document
	hash [32]byte
}

func read(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxFileSize {
		return nil, errors.New("vault exceeds size limit")
	}
	return b, nil
}

func Open(path string, password []byte) (*Store, domain.Document, error) {
	raw, err := read(path)
	if err != nil {
		return nil, domain.Document{}, err
	}
	d, h, key, err := decrypt(raw, password)
	if err != nil {
		return nil, domain.Document{}, err
	}
	s := &Store{Path: path, h: h, key: key, base: clone(d), hash: sha256.Sum256(raw)}
	return s, d, nil
}

func Create(path string, password []byte) (*Store, domain.Document, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, domain.Document{}, err
	}
	unlock, err := lock(path)
	if err != nil {
		return nil, domain.Document{}, err
	}
	defer unlock()
	if _, err := os.Lstat(path); err == nil {
		return nil, domain.Document{}, errors.New("vault already exists")
	} else if !os.IsNotExist(err) {
		return nil, domain.Document{}, err
	}
	h, key, err := newHeader(password)
	if err != nil {
		return nil, domain.Document{}, err
	}
	d := domain.NewDocument()
	raw, err := encrypt(d, h, key)
	if err != nil {
		wipe(key)
		return nil, d, err
	}
	if err = atomicWrite(path, raw); err != nil {
		wipe(key)
		return nil, d, err
	}
	return &Store{Path: path, h: h, key: key, base: clone(d), hash: sha256.Sum256(raw)}, d, nil
}

func clone(d domain.Document) domain.Document {
	raw, _ := json.Marshal(d)
	var out domain.Document
	_ = json.Unmarshal(raw, &out)
	wipe(raw)
	return out
}

func (s *Store) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	wipe(s.key)
	s.key = nil
	s.base = domain.Document{}
}

func lock(path string) (func(), error) {
	fd, err := unix.Open(path+".lock", unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = unix.Close(fd)
		return nil, errors.New("another instance is saving this vault; try again")
	}
	return func() { _ = unix.Flock(fd, unix.LOCK_UN); _ = unix.Close(fd) }, nil
}

func atomicWrite(path string, raw []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".sshm-encrypted-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (s *Store) external() (domain.Document, header, []byte, error) {
	raw, err := read(s.Path)
	if err != nil {
		return domain.Document{}, header{}, nil, err
	}
	var env envelope
	if err = json.Unmarshal(raw, &env); err != nil {
		return domain.Document{}, header{}, nil, errors.New("invalid external vault")
	}
	// A password change by another instance requires explicit reauthentication.
	a, _ := json.Marshal(s.h)
	b, _ := json.Marshal(env.Header)
	if !bytes.Equal(a, b) {
		return domain.Document{}, header{}, nil, errors.New("vault password or format changed; lock and reopen it")
	}
	d, err := decryptData(env, s.key)
	return d, env.Header, raw, err
}

func (s *Store) Save(local domain.Document) (domain.Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.save(local, "", nil)
}

func (s *Store) Preview(local domain.Document) (domain.Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	remote, _, _, err := s.external()
	if err != nil {
		return domain.Document{}, err
	}
	_, err = Merge(s.base, local, remote)
	return remote, err
}

func (s *Store) SaveResolved(local domain.Document, revision string, choices map[string]string) (domain.Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.save(local, revision, choices)
}

func (s *Store) save(local domain.Document, expected string, choices map[string]string) (domain.Document, error) {
	if len(s.key) == 0 {
		return local, errors.New("vault is locked")
	}
	if err := local.Validate(); err != nil {
		return local, err
	}
	unlock, err := lock(s.Path)
	if err != nil {
		return local, err
	}
	defer unlock()
	remote, h, old, err := s.external()
	if err != nil {
		return local, err
	}
	if expected != "" && remote.Revision != expected {
		return local, errors.New("vault changed during conflict resolution; save again to review new conflicts")
	}
	next, err := MergeSelected(s.base, local, remote, choices)
	if err != nil {
		return local, err
	}
	raw, err := encrypt(next, h, s.key)
	if err != nil {
		return local, err
	}
	// Keep the preceding encrypted revision for cloud races and recovery.
	backup := s.Path + ".backup-" + time.Now().UTC().Format("20060102T150405.000000000") + "-" + domain.NewID()[:8]
	if err = atomicWrite(backup, old); err != nil {
		return local, fmt.Errorf("cannot save encrypted backup: %w", err)
	}
	// Cloud clients do not honor our local lock: detect replacements before commit.
	current, err := read(s.Path)
	if err != nil {
		return local, err
	}
	if sha256.Sum256(current) != sha256.Sum256(old) {
		return local, errors.New("vault changed during save; try again")
	}
	if err = atomicWrite(s.Path, raw); err != nil {
		return local, err
	}
	s.base = clone(next)
	s.hash = sha256.Sum256(raw)
	return next, nil
}

func (s *Store) Refresh(local domain.Document) (domain.Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	remote, _, raw, err := s.external()
	if err != nil {
		return local, err
	}
	if sha256.Sum256(raw) == s.hash {
		return local, nil
	}
	out, err := Merge(s.base, local, remote)
	if err != nil {
		return local, err
	}
	s.base = clone(remote)
	s.hash = sha256.Sum256(raw)
	return out, nil
}

// Export writes a separate encrypted snapshot without touching the shared vault.
func (s *Store) Export(path string, local domain.Document) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.key) == 0 {
		return errors.New("vault is locked")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return errors.New("export destination already exists or cannot be checked")
	}
	raw, err := encrypt(local, s.h, s.key)
	if err != nil {
		return err
	}
	// O_EXCL avoids replacing a concurrent export.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(raw); err != nil {
		return err
	}
	return f.Sync()
}

func (s *Store) ChangePassword(local domain.Document, password []byte) (domain.Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.key) == 0 {
		return local, errors.New("vault is locked")
	}
	unlock, err := lock(s.Path)
	if err != nil {
		return local, err
	}
	defer unlock()
	remote, _, old, err := s.external()
	if err != nil {
		return local, err
	}
	next, err := Merge(s.base, local, remote)
	if err != nil {
		return local, err
	}
	h, newKey, err := newHeader(password)
	if err != nil {
		return local, err
	}
	defer wipe(newKey)
	// Rewrap the existing data key; subsequent writes keep using it.
	kek := derive(password, h)
	defer wipe(kek)
	if err = rewrap(&h, kek, s.key); err != nil {
		return local, err
	}
	raw, err := encrypt(next, h, s.key)
	if err != nil {
		return local, err
	}
	if err = atomicWrite(s.Path+".backup-"+domain.NewID(), old); err != nil {
		return local, err
	}
	current, err := read(s.Path)
	if err != nil {
		return local, err
	}
	if sha256.Sum256(current) != sha256.Sum256(old) {
		return local, errors.New("vault changed during password change; try again")
	}
	if err = atomicWrite(s.Path, raw); err != nil {
		return local, err
	}
	s.h = h
	s.base = clone(next)
	s.hash = sha256.Sum256(raw)
	return next, nil
}
