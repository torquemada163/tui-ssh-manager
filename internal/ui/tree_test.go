package ui

import (
	"reflect"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/torquemada163/tui-ssh-manager/internal/domain"
)

func treeFixture(t *testing.T) *Model {
	m := visualModel(t)
	m.selected = 0
	m.expanded = [3]map[string]bool{}
	m.doc.Folders = []domain.Folder{
		{ID: "z", Name: "Я"}, {ID: "a", Name: "А"},
		{ID: "child", Name: "Вложенная", ParentID: "a"},
		{ID: "empty", Name: "Пустая"},
	}
	m.doc.Connections = []domain.Connection{
		{ID: "root-z", Name: "я-сервер"}, {ID: "root-a", Name: "а-сервер"},
		{ID: "nested", Name: "Глубокий", FolderID: "child", Host: "find.test"},
		{ID: "direct", Name: "Прямой", FolderID: "a"},
	}
	return m
}

func assertRowIDs(t *testing.T, m *Model, want ...string) {
	t.Helper()
	var got []string
	for _, r := range m.rows() {
		got = append(got, r.id)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rows %v, want %v", got, want)
	}
}

func TestCatalogTreeStartsAtRootAndSortsFoldersFirst(t *testing.T) {
	m := treeFixture(t)
	assertRowIDs(t, m, "a", "empty", "z", "root-a", "root-z")
	if !strings.HasPrefix(m.treeName(m.rows()[0]), "▸ ") {
		t.Fatal("missing collapsed marker")
	}
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	assertRowIDs(t, m, "a", "child", "direct", "empty", "z", "root-a", "root-z")
	if !strings.HasPrefix(m.treeName(m.rows()[0]), "▾ ") {
		t.Fatal("missing expanded marker")
	}
	m.selected = 1
	m.Update(tea.KeyMsg{Type: tea.KeySpace})
	assertRowIDs(t, m, "a", "child", "nested", "direct", "empty", "z", "root-a", "root-z")
	if !strings.HasPrefix(m.treeName(m.rows()[2]), "      ") {
		t.Fatal("missing nested indentation")
	}
	m.selected = 0
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	assertRowIDs(t, m, "a", "empty", "z", "root-a", "root-z")
	if m.screen != "catalog" {
		t.Fatal("folder Enter opened an editor or SSH")
	}
	// Folders have their own expansion state and never contain connection rows.
	m.tab = 2
	assertRowIDs(t, m, "a", "empty", "z")
	m.toggleFolder()
	assertRowIDs(t, m, "a", "child", "empty", "z")
	if m.hasChildren("child") {
		t.Fatal("connections treated as children in folder catalog")
	}
}

func TestTreeSearchRevealsAncestorsAndRestoresCollapsedState(t *testing.T) {
	m := treeFixture(t)
	m.search.SetValue("find.test")
	assertRowIDs(t, m, "a", "child", "nested")
	if !strings.Contains(m.treeName(m.rows()[0]), "▾") {
		t.Fatal("search branch not marked open")
	}
	m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	assertRowIDs(t, m, "a", "empty", "z", "root-a", "root-z")
	m.tab = 2
	m.search.SetValue("Вложенная")
	assertRowIDs(t, m, "a", "child")
	m.search.SetValue("not found")
	assertRowIDs(t, m)
}

func TestTreeFolderFilterKeepsHierarchy(t *testing.T) {
	m := treeFixture(t)
	m.folderID = "a"
	assertRowIDs(t, m, "a")
	m.toggleFolder()
	assertRowIDs(t, m, "a", "child", "direct")
	if m.treeName(m.rows()[0]) != "▾ А" {
		t.Fatal("filtered root indented")
	}
	if m.treeName(m.rows()[1]) != "  ▸ Вложенная" {
		t.Fatal("filtered child indentation")
	}
}

func TestConnectionCatalogFolderActionsUseFolderObject(t *testing.T) {
	m := referenceFixture(t)
	m.form = nil
	m.screen = "catalog"
	for i, r := range m.rows() {
		if r.id == "parent" {
			m.selected = i
		}
	}
	if cmd := m.connect(true); cmd != nil || m.screen != "catalog" {
		t.Fatal("folder launched SSH")
	}
	m.edit(true)
	if m.form.purpose != "folder" || m.form.id != "parent" {
		t.Fatal("folder edited as connection")
	}
	m.form = nil
	m.screen = "catalog"
	m.confirmAction = "delete"
	if cmd := m.confirm(); cmd != nil || !m.isError || !strings.Contains(m.status, "Web") {
		t.Fatal("folder containing children was not protected from deletion")
	}
}
