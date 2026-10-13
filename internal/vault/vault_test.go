package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/torquemada163/tui-ssh-manager/internal/domain"
)

func fixture() domain.Document {
	d := domain.NewDocument()
	d.Credentials = []domain.Credential{{ID: "cred", Name: "administrator", Username: "alice", Kind: "password", Password: "secret-not-on-disk"}}
	d.Connections = []domain.Connection{{ID: "server", Name: "production-private", Host: "prod.example.org", Port: 22, CredentialIDs: []string{"cred"}}}
	return d
}

func TestVaultEncryptedRoundTripAndTampering(t *testing.T) {
	d := fixture()
	password := []byte("a-long-master-password")
	h, key, err := newHeader(password)
	if err != nil {
		t.Fatal(err)
	}
	defer wipe(key)
	raw, err := encrypt(d, h, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{d.Credentials[0].Password, d.Connections[0].Host, d.Connections[0].Name} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("plaintext metadata or secret written to vault")
		}
	}
	opened, _, openedKey, err := decrypt(raw, password)
	if err != nil {
		t.Fatal(err)
	}
	defer wipe(openedKey)
	if opened.Credentials[0].Password != d.Credentials[0].Password {
		t.Fatal("secret did not round trip")
	}
	if _, _, _, err = decrypt(raw, []byte("wrong-password")); err == nil {
		t.Fatal("wrong password accepted")
	}
	var env envelope
	if err = json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	env.Ciphertext[len(env.Ciphertext)/2] ^= 1
	corrupt, _ := json.Marshal(env)
	if _, _, _, err = decrypt(corrupt, password); err == nil {
		t.Fatal("corrupt ciphertext accepted")
	}
	if err = json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	env.Header.Threads = 3
	corrupt, _ = json.Marshal(env)
	if _, _, _, err = decrypt(corrupt, password); err == nil {
		t.Fatal("modified header accepted")
	}
}

func TestRejectUnboundedKDFBeforeDerivation(t *testing.T) {
	env := envelope{Header: header{Version: 1, Salt: make([]byte, 16), Memory: 1 << 30, Time: 1, Threads: 1, WrapNonce: make([]byte, 24), WrappedKey: make([]byte, 48)}, Nonce: make([]byte, 24)}
	raw, _ := json.Marshal(env)
	if _, _, _, err := decrypt(raw, []byte("password")); err == nil {
		t.Fatal("unbounded KDF accepted")
	}
}

func TestSeparateInstancesMergeAndProtectConflicts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "connections.sshvault")
	pw := []byte("a-long-master-password")
	a, d, err := Create(path, pw)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	d.Credentials = fixture().Credentials
	d.Connections = fixture().Connections
	d, err = a.Save(d)
	if err != nil {
		t.Fatal(err)
	}
	b, other, err := Open(path, pw)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	d.Connections[0].Host = "new.example.org"
	d, err = a.Save(d)
	if err != nil {
		t.Fatal(err)
	}
	other.Credentials[0].Username = "bob"
	other, err = b.Save(other)
	if err != nil {
		t.Fatal(err)
	}
	if other.Connections[0].Host != "new.example.org" || other.Credentials[0].Username != "bob" {
		t.Fatal("independent changes lost")
	}
	d, err = a.Refresh(d)
	if err != nil {
		t.Fatal(err)
	}
	d.Connections[0].Name = "local change"
	other.Connections[0].Name = "remote change"
	if _, err = b.Save(other); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Save(d)
	var conflict *Conflict
	if !errors.As(err, &conflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("conflict overwrote remote changes")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("vault not private")
	}
	backups, _ := filepath.Glob(path + ".backup-*")
	if len(backups) == 0 {
		t.Fatal("no encrypted backups")
	}
	for _, p := range backups {
		raw, _ := os.ReadFile(p)
		if bytes.Contains(raw, []byte("secret-not-on-disk")) {
			t.Fatal("plaintext backup")
		}
	}
}

func TestDeletionAgainstEditAndReferences(t *testing.T) {
	base := fixture()
	local, remote := clone(base), clone(base)
	local.Connections = nil
	remote.Connections[0].Host = "changed.example.org"
	if _, err := Merge(base, local, remote); err == nil {
		t.Fatal("delete vs edit did not conflict")
	}
	local, remote = clone(base), clone(base)
	local.Credentials = nil
	local.Connections = nil
	remote.Connections = append(remote.Connections, domain.Connection{ID: "extra", Name: "extra", Host: "extra.example.org", Port: 22, CredentialIDs: []string{"cred"}})
	if _, err := Merge(base, local, remote); err == nil {
		t.Fatal("dangling reference after merge accepted")
	}
}

func TestPasswordChangeRequiresOtherInstanceToReauthenticate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault")
	old := []byte("old-master-password")
	next := []byte("new-master-password")
	a, d, err := Create(path, old)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, stale, err := Open(path, old)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, err = a.ChangePassword(d, next); err != nil {
		t.Fatal(err)
	}
	if _, err = b.Save(stale); err == nil {
		t.Fatal("stale instance overwrote password change")
	}
	if _, _, err = Open(path, old); err == nil {
		t.Fatal("old password still opens vault")
	}
	c, _, err := Open(path, next)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestConcurrentSavesKeepBothEdits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault")
	pw := []byte("master-password-123")
	a, da, err := Create(path, pw)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, db, err := Open(path, pw)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	da.Folders = append(da.Folders, domain.Folder{ID: "a", Name: "a"})
	db.Folders = append(db.Folders, domain.Folder{ID: "b", Name: "b"})
	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); _, errs[0] = a.Save(da) }()
	go func() { defer wg.Done(); _, errs[1] = b.Save(db) }()
	wg.Wait()
	if errs[0] != nil {
		if _, err = a.Save(da); err != nil {
			t.Fatal(err)
		}
	}
	if errs[1] != nil {
		if _, err = b.Save(db); err != nil {
			t.Fatal(err)
		}
	}
	c, d, err := Open(path, pw)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if len(d.Folders) != 2 {
		t.Fatal("concurrent edits lost")
	}
}

func TestExplicitResolutionAndChangedRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault")
	pw := []byte("master-password-123")
	a, d, err := Create(path, pw)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	d.Credentials = fixture().Credentials
	d.Connections = fixture().Connections
	d, err = a.Save(d)
	if err != nil {
		t.Fatal(err)
	}
	b, other, err := Open(path, pw)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	d.Credentials[0].Password = "local-secret"
	other.Credentials[0].Password = "remote-secret"
	other, err = b.Save(other)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := a.Preview(d)
	var conflict *Conflict
	if !errors.As(err, &conflict) {
		t.Fatal("expected conflict preview")
	}
	other.Connections[0].Name = "additional edit"
	other, err = b.Save(other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.SaveResolved(d, remote.Revision, map[string]string{"credential:cred": "local"}); err == nil {
		t.Fatal("outdated conflict choices overwritten newer revision")
	}
	remote, err = a.Preview(d)
	if !errors.As(err, &conflict) {
		t.Fatal("expected new preview")
	}
	next, err := a.SaveResolved(d, remote.Revision, map[string]string{"credential:cred": "local"})
	if err != nil {
		t.Fatal(err)
	}
	if next.Credentials[0].Password != "local-secret" || next.Connections[0].Name != "additional edit" {
		t.Fatal("resolution lost chosen or independent edit")
	}
}

func TestCopyMergeKeepsObjectsAbsentFromCopy(t *testing.T) {
	local := fixture()
	other := clone(local)
	other.Connections = nil
	out, err := MergeCopy(local, other, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Connections) != 1 {
		t.Fatal("absence in imported copy deleted connection")
	}
	other = clone(local)
	other.Credentials[0].Password = "copy-secret"
	if _, err = MergeCopy(local, other, nil); err == nil {
		t.Fatal("copy disagreement accepted without choice")
	}
	out, err = MergeCopy(local, other, map[string]string{"credential:cred": "remote"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Credentials[0].Password != "copy-secret" {
		t.Fatal("copy choice not applied")
	}
}
