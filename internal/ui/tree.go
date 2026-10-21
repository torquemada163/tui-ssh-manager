package ui

import (
	"fmt"
	"sort"
	"strings"
)

func sortRows(rows []row) {
	sort.Slice(rows, func(i, j int) bool {
		a, b := strings.ToLower(rows[i].name), strings.ToLower(rows[j].name)
		if a == b {
			return rows[i].id < rows[j].id
		}
		return a < b
	})
}

// Both catalogs walk the same folder hierarchy. Search retains ancestors and
// reveals matching descendants without changing the user's expansion state.
func (m *Model) rows() []row {
	query := strings.ToLower(m.search.Value())
	matches := func(r row) bool { return strings.Contains(strings.ToLower(r.name+" "+r.detail), query) }
	if m.tab == 1 {
		var rows []row
		for _, c := range m.doc.Credentials {
			r := row{c.ID, c.Name, c.Username + " · " + c.Kind}
			if matches(r) {
				rows = append(rows, r)
			}
		}
		sortRows(rows)
		return rows
	}
	folders, connections := map[string][]row{}, map[string][]row{}
	for _, f := range m.doc.Folders {
		folders[f.ParentID] = append(folders[f.ParentID], row{f.ID, f.Name, m.folderName(f.ParentID)})
	}
	if m.tab == 0 {
		for _, c := range m.doc.Connections {
			connections[c.FolderID] = append(connections[c.FolderID], row{c.ID, c.Name, fmt.Sprintf("%s:%d · %s · %s", c.Host, c.Port, m.folderName(c.FolderID), c.Tags)})
		}
	}
	for _, rows := range folders {
		sortRows(rows)
	}
	for _, rows := range connections {
		sortRows(rows)
	}
	var walk func(string) []row
	walk = func(parent string) []row {
		var rows []row
		for _, f := range folders[parent] {
			children := walk(f.id)
			if query != "" && !matches(f) && len(children) == 0 {
				continue
			}
			rows = append(rows, f)
			if query != "" || m.expanded[m.tab][f.id] {
				rows = append(rows, children...)
			}
		}
		for _, c := range connections[parent] {
			if matches(c) {
				rows = append(rows, c)
			}
		}
		return rows
	}
	if m.tab == 0 && m.folderID != "" {
		for _, f := range m.doc.Folders {
			if f.ID == m.folderID {
				children := walk(f.ID)
				r := row{f.ID, f.Name, m.folderName(f.ParentID)}
				if query != "" && !matches(r) && len(children) == 0 {
					return nil
				}
				rows := []row{r}
				if query != "" || m.expanded[m.tab][f.ID] {
					rows = append(rows, children...)
				}
				return rows
			}
		}
	}
	return walk("")
}

func (m *Model) isFolder(r row) bool {
	if m.tab == 1 {
		return false
	}
	for _, f := range m.doc.Folders {
		if f.ID == r.id {
			return true
		}
	}
	return false
}

func (m *Model) selectedFolder() bool {
	rows := m.rows()
	return m.selected >= 0 && m.selected < len(rows) && m.isFolder(rows[m.selected])
}

func (m *Model) hasChildren(id string) bool {
	for _, f := range m.doc.Folders {
		if f.ParentID == id {
			return true
		}
	}
	if m.tab == 0 {
		for _, c := range m.doc.Connections {
			if c.FolderID == id {
				return true
			}
		}
	}
	return false
}

func (m *Model) toggleFolder() {
	if !m.selectedFolder() {
		return
	}
	id := m.rows()[m.selected].id
	if !m.hasChildren(id) {
		return
	}
	if m.search.Value() != "" {
		m.setStatus("Очистите поиск (Esc), чтобы свернуть папки", false)
		return
	}
	if m.expanded[m.tab] == nil {
		m.expanded[m.tab] = map[string]bool{}
	}
	m.expanded[m.tab][id] = !m.expanded[m.tab][id]
	m.clamp()
}

func (m *Model) treeName(r row) string {
	if m.tab == 1 {
		return clean(r.name)
	}
	parent := ""
	folder := m.isFolder(r)
	if folder {
		for _, f := range m.doc.Folders {
			if f.ID == r.id {
				parent = f.ParentID
				break
			}
		}
	} else {
		for _, c := range m.doc.Connections {
			if c.ID == r.id {
				parent = c.FolderID
				break
			}
		}
	}
	depth := 0
	for parent != "" && !(m.tab == 0 && r.id == m.folderID) {
		depth++
		if m.tab == 0 && parent == m.folderID {
			break
		}
		next := ""
		for _, f := range m.doc.Folders {
			if f.ID == parent {
				next = f.ParentID
				break
			}
		}
		parent = next
	}
	marker := "  "
	if folder {
		marker = "· "
		if m.hasChildren(r.id) {
			marker = "▸ "
			if m.expanded[m.tab][r.id] || m.search.Value() != "" {
				marker = "▾ "
			}
		}
	}
	return strings.Repeat("  ", depth) + marker + clean(r.name)
}
