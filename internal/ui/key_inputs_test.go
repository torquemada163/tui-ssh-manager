package ui

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/torquemada163/tui-ssh-manager/internal/domain"
	"github.com/torquemada163/tui-ssh-manager/internal/sshclient"
	"github.com/torquemada163/tui-ssh-manager/internal/vault"
	"golang.org/x/crypto/ssh"
)

func testKey(t *testing.T) string {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(block))
}

func credentialForm(t *testing.T) (*Model, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault")
	password := []byte("test-master-password")
	store, doc, err := vault.Create(path, password)
	if err != nil {
		t.Fatal(err)
	}
	m := New(path, &sshclient.Runner{}, 0)
	m.store = store
	m.doc = doc
	m.screen = "catalog"
	m.tab = 1
	m.edit(false)
	m.form.fields[0].input.SetValue("test-key")
	m.form.fields[1].input.SetValue("alice")
	t.Cleanup(m.Close)
	return m, path
}

func TestArrowNavigationAndAuthSelection(t *testing.T) {
	m := New(filepath.Join(t.TempDir(), "vault"), &sshclient.Runner{}, 0)
	m.doc = domain.NewDocument()
	m.screen = "catalog"
	_, _ = m.Update(tea.KeyMsg{Type: tea.KeyRight})
	if m.tab != 1 {
		t.Fatal("right did not select credentials")
	}
	_, _ = m.Update(tea.KeyMsg{Type: tea.KeyLeft})
	if m.tab != 0 {
		t.Fatal("left did not select connections")
	}
	_, _ = m.Update(tea.KeyMsg{Type: tea.KeyLeft})
	if m.tab != 2 {
		t.Fatal("catalog navigation does not wrap")
	}
	m.tab = 1
	m.edit(false)
	m.form.focus = 2
	_ = m.updateForm(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("invalid-type")})
	if m.form.fields[2].input.Value() != "agent" {
		t.Fatal("auth type accepts text")
	}
	_ = m.updateForm(tea.KeyMsg{Type: tea.KeyRight})
	if m.form.fields[2].input.Value() != "local-key" {
		t.Fatal("auth type did not cycle")
	}
	_ = m.updateForm(tea.KeyMsg{Type: tea.KeyRight})
	if m.form.fields[2].input.Value() != "stored-key" {
		t.Fatal("stored key not selectable")
	}
	_ = m.updateForm(tea.KeyMsg{Type: tea.KeyRight})
	_ = m.updateForm(tea.KeyMsg{Type: tea.KeyTab})
	if m.form.focus != 4 {
		t.Fatal("password form navigated to unused key path")
	}
	m.form.fields[4].input.SetValue("secret")
	before := m.form.fields[4].input.Value()
	_ = m.updateForm(tea.KeyMsg{Type: tea.KeyLeft})
	if m.tab != 1 || m.form.fields[4].input.Value() != before {
		t.Fatal("editing arrow switched catalog or changed password")
	}
}

func TestHiddenDirectoryBrowserSelectsLocalKey(t *testing.T) {
	m, path := credentialForm(t)
	root := filepath.Join(filepath.Dir(path), "files")
	hidden := filepath.Join(root, ".hidden")
	if err := os.MkdirAll(hidden, 0700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(hidden, ".id_ed25519")
	key := testKey(t)
	if err := os.WriteFile(keyPath, []byte(key), 0600); err != nil {
		t.Fatal(err)
	}
	m.form.fields[2].input.SetValue("local-key")
	m.form.fields[3].input.SetValue(root)
	m.form.focus = 3
	_ = m.updateForm(tea.KeyMsg{Type: tea.KeyEnter})
	if m.screen != "files" {
		t.Fatal("Enter did not open file browser")
	}
	if !strings.Contains(m.View(), ".hidden/") {
		t.Fatal("hidden directory missing from browser")
	}
	for i, entry := range m.browser.entries {
		if entry.name == ".hidden" {
			m.browser.selected = i
		}
	}
	_ = m.updateBrowser(tea.KeyMsg{Type: tea.KeyRight})
	if m.browser.directory != hidden {
		t.Fatal("directory not opened")
	}
	_ = m.updateBrowser(tea.KeyMsg{Type: tea.KeyLeft})
	if m.browser.directory != root || m.browser.entries[m.browser.selected].name != ".hidden" {
		t.Fatal("parent navigation did not preserve highlight")
	}
	_ = m.updateBrowser(tea.KeyMsg{Type: tea.KeyEnter})
	if !strings.Contains(m.View(), ".id_ed25519") {
		t.Fatal("hidden key file missing")
	}
	for i, entry := range m.browser.entries {
		if entry.name == ".id_ed25519" {
			m.browser.selected = i
		}
	}
	_ = m.updateBrowser(tea.KeyMsg{Type: tea.KeyEnter})
	if m.screen != "form" || m.form.fields[3].input.Value() != keyPath {
		t.Fatal("file selection not returned to form")
	}
	cmd := m.submit()
	if cmd == nil {
		t.Fatalf("credential rejected: %s", m.status)
	}
	_, _ = m.Update(cmd())
	s, d, err := vault.Open(path, []byte("test-master-password"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if len(d.Credentials) != 1 || d.Credentials[0].KeyPath != keyPath || d.Credentials[0].PrivateKey != "" {
		t.Fatal("local reference did not persist correctly")
	}
}

func TestStoredKeyFileAndPastePersistEncrypted(t *testing.T) {
	for _, source := range []string{"file", "terminal-paste", "clipboard"} {
		t.Run(source, func(t *testing.T) {
			m, path := credentialForm(t)
			key := testKey(t)
			m.form.fields[2].input.SetValue("stored-key")
			m.form.focus = 3
			switch source {
			case "file":
				keyPath := filepath.Join(filepath.Dir(path), "id_ed25519")
				if err := os.WriteFile(keyPath, []byte(key), 0600); err != nil {
					t.Fatal(err)
				}
				m.form.fields[3].input.SetValue(keyPath)
				_ = m.updateForm(tea.KeyMsg{Type: tea.KeyEnter})
				if m.screen != "key-source" {
					t.Fatal("stored-key source choice missing")
				}
				_ = m.updateKeySource(tea.KeyMsg{Type: tea.KeyEnter})
				_ = m.updateBrowser(tea.KeyMsg{Type: tea.KeyEnter})
			case "terminal-paste":
				_ = m.updateForm(tea.KeyMsg{Type: tea.KeyEnter})
				_ = m.updateKeySource(tea.KeyMsg{Type: tea.KeyRight})
				_ = m.updateKeySource(tea.KeyMsg{Type: tea.KeyEnter})
				_ = m.updateKeyPaste(tea.KeyMsg{Type: tea.KeyRunes, Paste: true, Runes: []rune(strings.ReplaceAll(key, "\n", "\r\n"))})
				if strings.Contains(m.View(), "BEGIN") && strings.Contains(m.View(), key) {
					t.Fatal("key shown in paste view")
				}
				_ = m.updateKeyPaste(tea.KeyMsg{Type: tea.KeyEnter})
			case "clipboard":
				m.clipboardReader = func() (string, error) { return key, nil }
				cmd := m.updateForm(tea.KeyMsg{Type: tea.KeyCtrlV})
				if cmd == nil {
					t.Fatal("clipboard not read on request")
				}
				_, _ = m.Update(cmd())
				_ = m.updateKeyPaste(tea.KeyMsg{Type: tea.KeyEnter})
			}
			if m.screen != "form" {
				t.Fatalf("key selection failed: %s", m.status)
			}
			if strings.Contains(m.View(), strings.Split(key, "\n")[1]) {
				t.Fatal("key contents shown in form")
			}
			cmd := m.submit()
			if cmd == nil {
				t.Fatalf("key rejected: %s", m.status)
			}
			_, _ = m.Update(cmd())
			s, d, err := vault.Open(path, []byte("test-master-password"))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if len(d.Credentials) != 1 || d.Credentials[0].PrivateKey != key {
				t.Fatal("imported key did not persist")
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), strings.Split(key, "\n")[1]) {
				t.Fatal("key written in plaintext")
			}
		})
	}
}

func TestCancelPasteAndStaleClipboardDoNotReplaceKey(t *testing.T) {
	m, _ := credentialForm(t)
	m.form.fields[2].input.SetValue("stored-key")
	m.form.keyDraft = "existing-key"
	m.form.focus = 3
	m.clipboardReader = func() (string, error) { return testKey(t), nil }
	cmd := m.updateForm(tea.KeyMsg{Type: tea.KeyCtrlV})
	_ = m.updateKeyPaste(tea.KeyMsg{Type: tea.KeyEsc})
	_, _ = m.Update(cmd())
	if m.screen != "form" || m.form.keyDraft != "existing-key" || m.pasteBuffer != "" {
		t.Fatal("cancelled clipboard request changed key")
	}
	m.openKeyPaste()
	m.acceptPastedKey("incomplete")
	_ = m.updateKeyPaste(tea.KeyMsg{Type: tea.KeyEnter})
	if m.screen != "paste-key" {
		t.Fatal("incomplete key accepted")
	}
	m.acceptPastedKey(strings.Repeat("x", maxKeyBytes))
	if len(m.pasteBuffer) >= maxKeyBytes {
		t.Fatal("unbounded key accepted")
	}
}

func TestMergeFileAndExportDirectoryUseBrowser(t *testing.T) {
	m, path := credentialForm(t)
	m.screen = "catalog"
	m.form = nil
	_, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("M")})
	_ = m.updateForm(tea.KeyMsg{Type: tea.KeyEnter})
	if m.screen != "files" || m.browser.field != 0 {
		t.Fatal("merge file browser not opened")
	}
	for i, entry := range m.browser.entries {
		if entry.path == path {
			m.browser.selected = i
		}
	}
	_ = m.updateBrowser(tea.KeyMsg{Type: tea.KeyEnter})
	if m.form.fields[0].input.Value() != path {
		t.Fatal("merge file not selected")
	}
	_ = m.updateForm(tea.KeyMsg{Type: tea.KeyEsc})
	_, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("E")})
	_ = m.updateForm(tea.KeyMsg{Type: tea.KeyEnter})
	if !m.browser.directoryMode {
		t.Fatal("export browser is not choosing a directory")
	}
	_ = m.updateBrowser(tea.KeyMsg{Type: tea.KeyCtrlS})
	if m.screen != "form" || m.form.fields[0].input.Value() != filepath.Dir(path) {
		t.Fatal("export destination not selected")
	}
	name := m.form.fields[1].input.Value()
	cmd := m.submit()
	if cmd == nil {
		t.Fatalf("export rejected: %s", m.status)
	}
	_, _ = m.Update(cmd())
	if m.isError {
		t.Fatal(m.status)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), name)); err != nil {
		t.Fatal(err)
	}
}
