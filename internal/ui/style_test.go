package ui

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/torquemada163/tui-ssh-manager/internal/domain"
	"github.com/torquemada163/tui-ssh-manager/internal/sshclient"
)

func visualModel(t *testing.T) *Model {
	t.Helper()
	m := New(filepath.Join(t.TempDir(), "test.sshvault"), &sshclient.Runner{}, 0)
	t.Cleanup(m.Close)
	m.doc = domain.NewDocument()
	m.form = nil
	m.screen = "catalog"
	m.doc.Credentials = []domain.Credential{{ID: "cred", Name: "deploy", Username: "alice", Kind: "stored-key", PrivateKey: "private-key-must-not-appear", Password: "password-must-not-appear", Passphrase: "passphrase-must-not-appear"}}
	m.doc.Folders = []domain.Folder{{ID: "folder", Name: "Рабочие серверы", CredentialIDs: []string{"cred"}}}
	for i := 0; i < 40; i++ {
		m.doc.Connections = append(m.doc.Connections, domain.Connection{ID: fmt.Sprint(i), Name: fmt.Sprintf("server-%02d", i), Host: "example.test", Port: 22, FolderID: "folder", Notes: strings.Repeat("長い заметки ", 20)})
	}
	m.expanded[0] = map[string]bool{"folder": true}
	m.selected = 40
	return m
}

func assertFits(t *testing.T, m *Model) {
	t.Helper()
	view := m.View()
	for _, line := range strings.Split(view, "\n") {
		if lipgloss.Width(line) > m.width {
			t.Fatalf("width %d > %d: %q", lipgloss.Width(line), m.width, line)
		}
	}
	if lipgloss.Height(view) > m.height {
		t.Fatalf("height %d > %d:\n%s", lipgloss.Height(view), m.height, ansi.Strip(view))
	}
}

func TestCatalogLayoutKeepsSelectionVisibleAndFitsTerminal(t *testing.T) {
	for _, size := range [][2]int{{120, 35}, {100, 24}, {80, 40}, {80, 24}, {40, 24}, {32, 12}, {20, 8}, {1, 1}} {
		t.Run(fmt.Sprintf("%dx%d", size[0], size[1]), func(t *testing.T) {
			m := visualModel(t)
			m.width, m.height = size[0], size[1]
			assertFits(t, m)
			if m.width >= 32 && m.height >= 12 && !strings.Contains(ansi.Strip(m.View()), "server-39") {
				t.Fatal("selected row scrolled out of view")
			}
			if m.width >= 96 && m.height >= 24 && !strings.Contains(m.View(), "example.test") {
				t.Fatal("selected connection details missing")
			}
		})
	}
}

func TestDetailsFollowFilteredSelectionAndHideSecrets(t *testing.T) {
	m := visualModel(t)
	m.selected = 0
	m.search.SetValue("server-07")
	m.selected = 1
	view := ansi.Strip(m.View())
	if !strings.Contains(view, "server-07") || strings.Contains(view, "server-00") {
		t.Fatal("details do not match filtered selection")
	}
	for tab := 0; tab < 3; tab++ {
		m.tab = tab
		m.selected = 0
		m.search.SetValue("")
		view = m.View()
		for _, secret := range []string{"private-key-must-not-appear", "password-must-not-appear", "passphrase-must-not-appear"} {
			if strings.Contains(view, secret) {
				t.Fatalf("tab %d exposes secret", tab)
			}
		}
	}
	m.tab = 1
	if !strings.Contains(ansi.Strip(m.View()), "••••••••") {
		t.Fatal("saved secret indication missing")
	}
}

func TestFormsAndPickersKeepFocusVisibleAfterResize(t *testing.T) {
	for _, size := range [][2]int{{120, 35}, {80, 24}, {40, 24}, {32, 16}} {
		t.Run(fmt.Sprintf("%dx%d", size[0], size[1]), func(t *testing.T) {
			m := visualModel(t)
			m.tab = 0
			m.edit(true)
			_, _ = m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
			m.form.focus = len(m.form.fields) - 1
			assertFits(t, m)
			if !strings.Contains(ansi.Strip(m.View()), m.form.fields[m.form.focus].label) {
				t.Fatal("focused field hidden")
			}
			m.screen = "files"
			m.browser = &fileBrowser{directory: "/tmp", entries: []fileEntry{{name: "selected-file"}}, selected: 0}
			assertFits(t, m)
			if !strings.Contains(m.View(), "selected-file") {
				t.Fatal("selected file hidden")
			}
		})
	}
}

func TestSecondaryScreensFitTerminal(t *testing.T) {
	for _, size := range [][2]int{{120, 35}, {80, 24}, {40, 24}, {32, 16}} {
		for _, screen := range []string{"locked", "references", "credentials", "folders", "key-source", "paste-key", "conflicts", "confirm"} {
			t.Run(fmt.Sprintf("%s/%dx%d", screen, size[0], size[1]), func(t *testing.T) {
				m := visualModel(t)
				m.width, m.height = size[0], size[1]
				m.selected = 0
				m.screen = screen
				switch screen {
				case "locked":
					m.locked()
				case "references":
					m.referencePicker = &referencePicker{title: "Выберите креды", multiple: true, checked: map[string]bool{}, options: m.rows()}
					m.referencePicker.cursor = 39
				case "credentials", "folders":
					m.choices = m.rows()
					m.choice = 39
				case "conflicts":
					m.conflictRemote = copyDoc(m.doc)
					m.decisions = map[string]string{}
					for _, c := range m.doc.Connections {
						m.conflictIDs = append(m.conflictIDs, "connection:"+c.ID)
					}
					m.conflictPos = 39
				}
				assertFits(t, m)
			})
		}
	}
}
