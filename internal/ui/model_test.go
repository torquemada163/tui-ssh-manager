package ui

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/torquemada163/tui-ssh-manager/internal/domain"
	"github.com/torquemada163/tui-ssh-manager/internal/sshclient"
	"github.com/torquemada163/tui-ssh-manager/internal/vault"
)

func TestFailedUnlockAllowsRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault")
	s, _, err := vault.Create(path, []byte("master-password-123"))
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	m := New(path, &sshclient.Runner{}, 0)
	defer m.Close()
	m.form.fields[0].input.SetValue("incorrect-password")
	cmd := m.submit()
	_, _ = m.Update(cmd())
	if m.screen != "locked" || m.form == nil {
		t.Fatal("unlock form lost after wrong password")
	}
	m.form.fields[0].input.SetValue("master-password-123")
	cmd = m.submit()
	_, _ = m.Update(cmd())
	if m.screen != "catalog" || m.store == nil {
		t.Fatal("retry did not unlock")
	}
}

func TestCredentialAndConflictViewsMaskSecrets(t *testing.T) {
	m := New(filepath.Join(t.TempDir(), "vault"), &sshclient.Runner{}, 0)
	d := domain.NewDocument()
	d.Credentials = []domain.Credential{{ID: "cred", Name: "admin", Username: "alice", Kind: "password", Password: "do-not-render-this"}}
	m.doc = d
	m.tab = 1
	m.screen = "catalog"
	m.edit(true)
	if strings.Contains(m.View(), "do-not-render-this") {
		t.Fatal("password rendered in edit form")
	}
	remote := copyDoc(d)
	remote.Credentials[0].Password = "other-secret"
	m.beginConflict(remote, &vault.Conflict{Objects: []string{"credential:cred"}}, false)
	view := m.View()
	if strings.Contains(view, "do-not-render-this") || strings.Contains(view, "other-secret") {
		t.Fatal("conflict view reveals secrets")
	}
	if cmd := m.updateConflicts(tea.KeyMsg{Type: tea.KeyEnter}); cmd != nil {
		t.Fatal("unreviewed conflict submitted")
	}
	_ = m.updateConflicts(tea.KeyMsg{Type: tea.KeyRight})
	if m.decisions["credential:cred"] != "remote" {
		t.Fatal("version choice not recorded")
	}
}

func TestInvalidEditDoesNotChangeDocument(t *testing.T) {
	m := New(filepath.Join(t.TempDir(), "vault"), &sshclient.Runner{}, 0)
	m.doc = domain.NewDocument()
	m.tab = 0
	m.screen = "catalog"
	m.edit(false)
	m.form.fields[0].input.SetValue("invalid")
	m.form.fields[1].input.SetValue("-oProxyCommand=evil")
	if cmd := m.submit(); cmd != nil {
		t.Fatal("invalid connection queued for save")
	}
	if len(m.doc.Connections) != 0 || m.screen != "form" {
		t.Fatal("invalid edit changed state")
	}
	_, _ = m.Update(unlockedMsg{err: errors.New("failed")})
	if m.form == nil {
		t.Fatal("error recovery lost input form")
	}
}
