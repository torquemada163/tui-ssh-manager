package ui

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/torquemada163/tui-ssh-manager/internal/domain"
	"github.com/torquemada163/tui-ssh-manager/internal/sshclient"
	"github.com/torquemada163/tui-ssh-manager/internal/vault"
)

func referenceFixture(t *testing.T) *Model {
	t.Helper()
	m, path := credentialForm(t)
	m.doc.Credentials = []domain.Credential{
		{ID: "alpha", Name: "Alpha", Username: "alice", Kind: "agent"},
		{ID: "beta", Name: "Beta, emergency", Username: "bob", Kind: "password", Password: "not-for-display"},
		{ID: "gamma", Name: "Gamma", Username: "carol", Kind: "agent"},
	}
	m.doc.Folders = []domain.Folder{
		{ID: "parent", Name: "Production", CredentialIDs: []string{"alpha", "beta"}},
		{ID: "child", Name: "Web", ParentID: "parent"},
		{ID: "other", Name: "Development", CredentialIDs: []string{"gamma"}},
	}
	d, err := m.store.Save(m.doc)
	if err != nil {
		t.Fatal(err)
	}
	m.doc = d
	m.path = path
	m.tab = 0
	m.edit(false)
	m.form.fields[1].input.SetValue("localhost")
	return m
}

func openReference(t *testing.T, m *Model, field int) {
	t.Helper()
	m.form.focus = field
	_ = m.updateForm(tea.KeyMsg{Type: tea.KeyEnter})
	if m.screen != "references" {
		t.Fatal("reference browser did not open")
	}
}
func highlightReference(t *testing.T, m *Model, id string) {
	t.Helper()
	for i, r := range m.referencePicker.rows() {
		if r.id == id {
			m.referencePicker.cursor = i
			return
		}
	}
	t.Fatalf("option %s not found", id)
}

func TestMultipleCredentialSelectionPersistsIDsAndSurvivesRename(t *testing.T) {
	m := referenceFixture(t)
	openReference(t, m, 4)
	for _, id := range []string{"alpha", "beta"} {
		highlightReference(t, m, id)
		_ = m.updateReferencePicker(tea.KeyMsg{Type: tea.KeySpace})
	}
	if strings.Contains(m.View(), "not-for-display") {
		t.Fatal("browser displayed secret")
	}
	_ = m.updateReferencePicker(tea.KeyMsg{Type: tea.KeyEnter})
	openReference(t, m, 5)
	highlightReference(t, m, "beta")
	_ = m.updateReferencePicker(tea.KeyMsg{Type: tea.KeyEnter})
	// Reference fields cannot be edited as free text or converted to names.
	m.form.focus = 4
	_ = m.updateForm(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("invalid name")})
	m.doc.Credentials[1].Name = "Renamed profile"
	cmd := m.submit()
	if cmd == nil {
		t.Fatalf("save rejected: %s", m.status)
	}
	_, _ = m.Update(cmd())
	s, d, err := vault.Open(m.path, []byte("test-master-password"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if len(d.Connections) != 1 {
		t.Fatal("connection not saved")
	}
	c := d.Connections[0]
	if !reflect.DeepEqual(c.CredentialIDs, []string{"alpha", "beta"}) || c.DefaultCredentialID != "beta" || c.Name != "localhost" {
		t.Fatalf("invalid assignments: %+v", c)
	}
}

func TestSelectionSearchKeepsHiddenChecksAndCancelKeepsOriginal(t *testing.T) {
	m := referenceFixture(t)
	m.form.references[4] = []string{"alpha"}
	openReference(t, m, 4)
	_ = m.updateReferencePicker(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("/")})
	_ = m.updateReferencePicker(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("bob")})
	_ = m.updateReferencePicker(tea.KeyMsg{Type: tea.KeyEnter})
	if len(m.referencePicker.rows()) != 1 {
		t.Fatal("search did not filter by user")
	}
	_ = m.updateReferencePicker(tea.KeyMsg{Type: tea.KeySpace})
	_ = m.updateReferencePicker(tea.KeyMsg{Type: tea.KeyEnter})
	if !reflect.DeepEqual(m.form.references[4], []string{"alpha", "beta"}) {
		t.Fatal("filter lost selected hidden row")
	}
	openReference(t, m, 4)
	highlightReference(t, m, "alpha")
	_ = m.updateReferencePicker(tea.KeyMsg{Type: tea.KeySpace})
	_ = m.updateReferencePicker(tea.KeyMsg{Type: tea.KeyEsc})
	if !reflect.DeepEqual(m.form.references[4], []string{"alpha", "beta"}) {
		t.Fatal("cancel changed assignments")
	}
}

func TestDefaultOptionsRespectInheritanceAndResetWhenAssignmentChanges(t *testing.T) {
	m := referenceFixture(t)
	openReference(t, m, 3)
	highlightReference(t, m, "child")
	_ = m.updateReferencePicker(tea.KeyMsg{Type: tea.KeyEnter})
	if !strings.Contains(m.referenceFieldView(4), "Alpha") {
		t.Fatal("inheritance not shown in form")
	}
	openReference(t, m, 5)
	for _, option := range m.referencePicker.options {
		if option.id == "gamma" {
			t.Fatal("unassigned default offered")
		}
	}
	highlightReference(t, m, "beta")
	_ = m.updateReferencePicker(tea.KeyMsg{Type: tea.KeyEnter})
	openReference(t, m, 4)
	highlightReference(t, m, "gamma")
	_ = m.updateReferencePicker(tea.KeyMsg{Type: tea.KeySpace})
	_ = m.updateReferencePicker(tea.KeyMsg{Type: tea.KeyEnter})
	if len(m.form.references[5]) != 0 {
		t.Fatal("invalid inherited default was not reset")
	}
	openReference(t, m, 5)
	if len(m.referencePicker.options) != 2 || m.referencePicker.options[1].id != "gamma" {
		t.Fatal("default picker does not use explicit assignments")
	}
	_ = m.updateReferencePicker(tea.KeyMsg{Type: tea.KeyEsc})
	openReference(t, m, 4)
	highlightReference(t, m, "")
	_ = m.updateReferencePicker(tea.KeyMsg{Type: tea.KeySpace})
	_ = m.updateReferencePicker(tea.KeyMsg{Type: tea.KeyEnter})
	if len(m.form.references[4]) != 0 || !strings.Contains(m.referenceFieldView(4), "Alpha") {
		t.Fatal("inheritance not restored")
	}
}

func TestFolderParentPickerExcludesSelfAndDescendants(t *testing.T) {
	m := referenceFixture(t)
	m.tab = 2
	m.screen = "catalog"
	for i, r := range m.rows() {
		if r.id == "parent" {
			m.selected = i
		}
	}
	m.edit(true)
	openReference(t, m, 1)
	for _, option := range m.referencePicker.options {
		if option.id == "parent" || option.id == "child" {
			t.Fatal("cyclic parent offered")
		}
	}
	_ = m.updateReferencePicker(tea.KeyMsg{Type: tea.KeyEsc})
	openReference(t, m, 2)
	if !m.referencePicker.checked["alpha"] || !m.referencePicker.checked["beta"] {
		t.Fatal("folder credential assignments not initialized")
	}
	highlightReference(t, m, "gamma")
	_ = m.updateReferencePicker(tea.KeyMsg{Type: tea.KeySpace})
	_ = m.updateReferencePicker(tea.KeyMsg{Type: tea.KeyEnter})
	cmd := m.submit()
	if cmd == nil {
		t.Fatal(m.status)
	}
	_, _ = m.Update(cmd())
	for _, folder := range m.doc.Folders {
		if folder.ID == "parent" && !reflect.DeepEqual(folder.CredentialIDs, []string{"alpha", "beta", "gamma"}) {
			t.Fatal("folder profiles not saved")
		}
	}
}

func TestEmptyCredentialBrowserCanCancelOrInherit(t *testing.T) {
	m := New(filepath.Join(t.TempDir(), "vault"), &sshclient.Runner{}, 0)
	m.doc = domain.NewDocument()
	m.tab = 0
	m.edit(false)
	openReference(t, m, 4)
	if len(m.referencePicker.options) != 1 {
		t.Fatal("empty browser missing inheritance option")
	}
	_ = m.updateReferencePicker(tea.KeyMsg{Type: tea.KeyEnter})
	if len(m.form.references[4]) != 0 || m.screen != "form" {
		t.Fatal("empty browser did not return to form")
	}
}

func TestCredentialNamesCanBeGeneratedWithoutTyping(t *testing.T) {
	m, path := credentialForm(t)
	m.form.fields[0].input.SetValue("")
	for i := 0; i < 2; i++ {
		cmd := m.submit()
		if cmd == nil {
			t.Fatal(m.status)
		}
		_, _ = m.Update(cmd())
		if i == 0 {
			m.tab = 1
			m.edit(false)
			m.form.fields[1].input.SetValue("alice")
		}
	}
	s, d, err := vault.Open(path, []byte("test-master-password"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if len(d.Credentials) != 2 || d.Credentials[0].Name == d.Credentials[1].Name {
		t.Fatal("generated profile names collide")
	}
}
