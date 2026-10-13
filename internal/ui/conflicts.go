package ui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/torquemada163/tui-ssh-manager/internal/domain"
	"github.com/torquemada163/tui-ssh-manager/internal/vault"
)

func (m *Model) beginConflict(remote domain.Document, c *vault.Conflict, fromCopy bool) {
	m.conflictRemote = remote
	m.conflictIDs = c.Objects
	m.conflictImport = fromCopy
	m.decisions = map[string]string{}
	m.conflictPos = 0
	m.screen = "conflicts"
	m.setStatus("", false)
}

func (m *Model) describeConflict(d domain.Document, key string) string {
	kind, id, _ := strings.Cut(key, ":")
	switch kind {
	case "credential":
		for _, c := range d.Credentials {
			if c.ID == id {
				return clean(fmt.Sprintf("Креды %s · %s · %s · секреты скрыты", c.Name, c.Username, c.Kind))
			}
		}
	case "connection":
		for _, c := range d.Connections {
			if c.ID == id {
				return clean(fmt.Sprintf("Соединение %s · %s:%d · %s", c.Name, c.Host, c.Port, c.Notes))
			}
		}
	case "folder":
		for _, f := range d.Folders {
			if f.ID == id {
				return clean("Папка " + f.Name)
			}
		}
	}
	return kind + ": удалён"
}

func (m *Model) updateConflicts(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "esc":
		m.screen = "catalog"
		m.conflictRemote = domain.Document{}
		m.conflictIDs = nil
		m.decisions = nil
	case "up", "k":
		if m.conflictPos > 0 {
			m.conflictPos--
		}
	case "down", "j":
		if m.conflictPos < len(m.conflictIDs)-1 {
			m.conflictPos++
		}
	case "left":
		m.decisions[m.conflictIDs[m.conflictPos]] = "local"
	case "right":
		m.decisions[m.conflictIDs[m.conflictPos]] = "remote"
	case "enter", "ctrl+s":
		for _, key := range m.conflictIDs {
			if m.decisions[key] == "" {
				m.setStatus("Выберите версию каждого объекта стрелками ←/→", true)
				return nil
			}
		}
		local, remote, choices := m.doc, m.conflictRemote, m.decisions
		if m.conflictImport {
			d, err := vault.MergeCopy(local, remote, choices)
			if err != nil {
				m.setStatus(err.Error(), true)
				return nil
			}
			m.conflictRemote = domain.Document{}
			m.conflictIDs = nil
			m.decisions = nil
			return m.save(d)
		}
		store := m.store
		m.screen = "busy"
		m.conflictRemote = domain.Document{}
		m.conflictIDs = nil
		m.decisions = nil
		return func() tea.Msg {
			d, err := store.SaveResolved(local, remote.Revision, choices)
			return savedMsg{d, err, "Конфликт разрешён, изменения сохранены"}
		}
	}
	return nil
}
