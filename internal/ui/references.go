package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/torquemada163/tui-ssh-manager/internal/domain"
)

type referencePicker struct {
	field     int
	title     string
	options   []row
	multiple  bool
	checked   map[string]bool
	cursor    int
	query     textinput.Model
	searching bool
}

func optionalID(id string) []string {
	if id == "" {
		return nil
	}
	return []string{id}
}
func firstID(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	return ids[0]
}

func (f *form) isReferenceField(index int) bool {
	return f.purpose == "connection" && index >= 3 && index <= 5 || f.purpose == "folder" && (index == 1 || index == 2)
}

func (m *Model) draftConnection() domain.Connection {
	f := m.form
	return domain.Connection{ID: f.id, FolderID: firstID(f.references[3]), CredentialIDs: f.references[4], DefaultCredentialID: firstID(f.references[5])}
}

func (m *Model) reconcileDefaultCredential() {
	if m.form.purpose != "connection" {
		return
	}
	current := firstID(m.form.references[5])
	if current == "" {
		return
	}
	for _, id := range m.doc.EffectiveCredentials(m.draftConnection()) {
		if id == current {
			return
		}
	}
	m.form.references[5] = nil
	m.setStatus("Профиль по умолчанию сброшен: он больше не назначен соединению", false)
}

func (m *Model) folderPath(id string) string {
	var parts []string
	seen := map[string]bool{}
	for id != "" && !seen[id] {
		seen[id] = true
		found := false
		for _, folder := range m.doc.Folders {
			if folder.ID == id {
				parts = append(parts, folder.Name)
				id = folder.ParentID
				found = true
				break
			}
		}
		if !found {
			break
		}
	}
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, " / ")
}

func (m *Model) referenceFieldView(index int) string {
	f := m.form
	ids := f.references[index]
	folderField := f.purpose == "connection" && index == 3 || f.purpose == "folder" && index == 1
	if folderField {
		if len(ids) > 0 {
			return clean(m.folderPath(ids[0])) + " · Enter изменить"
		}
		return "[ Без папки ] · Enter выбрать"
	}
	if len(ids) > 0 {
		return clean(m.credentialNames(ids)) + " · Enter изменить"
	}
	if f.purpose == "connection" && index == 5 {
		return "[ Автоматически / спросить при подключении ] · Enter выбрать"
	}
	if f.purpose == "connection" {
		if inherited := m.doc.EffectiveCredentials(m.draftConnection()); len(inherited) > 0 {
			return "Наследовать: " + clean(m.credentialNames(inherited)) + " · Enter изменить"
		}
	}
	return "[ Наследовать от родительской папки ] · Enter выбрать"
}

func (m *Model) openReferencePicker() {
	f := m.form
	index := f.focus
	p := &referencePicker{field: index, checked: map[string]bool{}, query: textinput.New()}
	p.query.Placeholder = "Имя, пользователь или тип"
	p.query.CharLimit = 256
	p.query.Width = 50
	for _, id := range f.references[index] {
		p.checked[id] = true
	}
	folderField := f.purpose == "connection" && index == 3 || f.purpose == "folder" && index == 1
	if folderField {
		p.title = "Выберите папку"
		emptyLabel := "Без папки"
		if f.purpose == "folder" {
			p.title = "Выберите родительскую папку"
			emptyLabel = "Без родительской папки"
		}
		p.options = []row{{id: "", name: emptyLabel}}
		var folders []row
		for _, folder := range m.doc.Folders {
			if f.purpose == "folder" && f.id != "" && m.inFolder(folder.ID, f.id) {
				continue
			}
			folders = append(folders, row{id: folder.ID, name: m.folderPath(folder.ID)})
		}
		sort.Slice(folders, func(i, j int) bool { return strings.ToLower(folders[i].name) < strings.ToLower(folders[j].name) })
		p.options = append(p.options, folders...)
	} else {
		p.title = "Выберите креды"
		p.multiple = true
		p.options = []row{{id: "", name: "Наследовать от родительской папки"}}
		var eligible map[string]bool
		if f.purpose == "connection" && index == 5 {
			p.title = "Выберите профиль по умолчанию"
			p.multiple = false
			p.options = []row{{id: "", name: "Автоматически / спросить при подключении"}}
			eligible = map[string]bool{}
			for _, id := range m.doc.EffectiveCredentials(m.draftConnection()) {
				eligible[id] = true
			}
		}
		var credentials []row
		for _, credential := range m.doc.Credentials {
			if eligible != nil && !eligible[credential.ID] {
				continue
			}
			credentials = append(credentials, row{id: credential.ID, name: credential.Name, detail: credential.Username + " · " + authLabel(credential.Kind)})
		}
		sort.Slice(credentials, func(i, j int) bool {
			return strings.ToLower(credentials[i].name) < strings.ToLower(credentials[j].name)
		})
		p.options = append(p.options, credentials...)
	}
	if !p.multiple {
		for i, option := range p.options {
			if p.checked[option.id] {
				p.cursor = i
				break
			}
		}
	}
	m.referencePicker = p
	m.screen = "references"
	m.setStatus("", false)
}

func (p *referencePicker) rows() []row {
	query := strings.ToLower(p.query.Value())
	var matches []row
	for _, option := range p.options {
		if strings.Contains(strings.ToLower(option.name+" "+option.detail), query) {
			matches = append(matches, option)
		}
	}
	return matches
}

func (m *Model) updateReferencePicker(msg tea.KeyMsg) tea.Cmd {
	p := m.referencePicker
	if p.searching {
		switch msg.String() {
		case "esc":
			p.query.SetValue("")
			p.searching = false
			p.query.Blur()
			p.cursor = 0
			return nil
		case "enter":
			p.searching = false
			p.query.Blur()
			return nil
		}
		var cmd tea.Cmd
		p.query, cmd = p.query.Update(msg)
		p.cursor = 0
		return cmd
	}
	rows := p.rows()
	switch msg.String() {
	case "esc":
		m.referencePicker = nil
		m.screen = "form"
		m.setStatus("", false)
	case "/":
		p.searching = true
		p.query.Focus()
		return textinput.Blink
	case "up", "k":
		if p.cursor > 0 {
			p.cursor--
		}
	case "down", "j":
		if p.cursor < len(rows)-1 {
			p.cursor++
		}
	case "home":
		p.cursor = 0
	case "end":
		if len(rows) > 0 {
			p.cursor = len(rows) - 1
		}
	case " ":
		if !p.multiple || len(rows) == 0 {
			return nil
		}
		id := rows[p.cursor].id
		if id == "" {
			p.checked = map[string]bool{}
		} else {
			if p.checked[id] {
				delete(p.checked, id)
			} else {
				p.checked[id] = true
			}
		}
	case "ctrl+u":
		p.checked = map[string]bool{}
	case "enter", "ctrl+s":
		var ids []string
		if p.multiple {
			// Commit every check, including rows hidden by the current filter.
			for _, option := range p.options {
				if option.id != "" && p.checked[option.id] {
					ids = append(ids, option.id)
				}
			}
		} else {
			if len(rows) == 0 {
				m.setStatus("Нет подходящих вариантов", true)
				return nil
			}
			ids = optionalID(rows[p.cursor].id)
		}
		m.form.references[p.field] = ids
		m.referencePicker = nil
		m.screen = "form"
		m.setStatus("Выбор применён", false)
		m.reconcileDefaultCredential()
	}
	return nil
}

func (m *Model) referencePickerView() string {
	p := m.referencePicker
	var view strings.Builder

	if p.multiple {
		view.WriteString(fmt.Sprintf("Выбрано профилей: %d\n", len(p.checked)))
	}
	if p.searching {
		query := p.query
		query.Width = max(1, m.width-15)
		view.WriteString("Поиск: " + query.View() + "\n")
	} else if p.query.Value() != "" {
		view.WriteString("Поиск: " + clean(p.query.Value()) + "\n")
	}
	rows := p.rows()
	limit := m.height - 19
	if limit < 1 {
		limit = 1
	}
	start := 0
	if p.cursor >= limit {
		start = p.cursor - limit + 1
	}
	for i := start; i < len(rows) && i < start+limit; i++ {
		option := rows[i]
		prefix := "  "
		if p.multiple {
			checked := p.checked[option.id] || option.id == "" && len(p.checked) == 0
			if checked {
				prefix = "[x] "
			} else {
				prefix = "[ ] "
			}
		}
		line := prefix + clean(option.name)
		if option.detail != "" {
			line += " · " + clean(option.detail)
		}
		if i == p.cursor {
			view.WriteString(selectedLine("› "+line, m.width-8) + "\n")
		} else {
			view.WriteString("  " + line + "\n")
		}
	}
	if len(rows) == 0 {
		view.WriteString("Нет подходящих вариантов\n")
	}
	if len(p.options) == 1 && !strings.Contains(p.title, "папку") {
		view.WriteString("\nСначала назначьте или создайте профили в каталоге «Креды».\n")
	}
	view.WriteString("\n" + muted.Render("↑/↓ выбрать · / поиск · Enter применить · Esc отменить"))
	if p.multiple {
		view.WriteString("\n" + muted.Render("Пробел отметить/снять · Ctrl+U снять все · пустой список = наследование"))
	}
	return view.String()
}
