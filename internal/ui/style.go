package ui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

var (
	accent        = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#146B8C", Dark: "#72D5E8"}).Bold(true)
	muted         = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#626B79", Dark: "#939EAE"})
	danger        = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#B42336", Dark: "#FF8791"})
	borderColor   = lipgloss.AdaptiveColor{Light: "#B1BDCC", Dark: "#455369"}
	selectedStyle = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#153C59", Dark: "#E2F4FF"}).Background(lipgloss.AdaptiveColor{Light: "#DFEDF7", Dark: "#243C52"}).Bold(true)
	tabStyle      = lipgloss.NewStyle().Padding(0, 1)
)

func fitLine(s string, width int) string {
	if width <= 0 {
		return ""
	}
	return ansi.Truncate(s, width, "…")
}

func selectedLine(s string, width int) string {
	return selectedStyle.Width(max(1, width)).Render(fitLine(s, width))
}

// Width includes the border and horizontal padding. Content contains display
// data only: secrets are never passed to the detail renderer.
func panel(title, content string, width, height int) string {
	inner := max(1, width-4)
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	for i := range lines {
		lines[i] = fitLine(lines[i], inner)
	}
	body := accent.Render(fitLine(title, inner)) + "\n\n" + strings.Join(lines, "\n")
	style := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(borderColor).Padding(0, 1).Width(max(1, width-2))
	if height > 0 {
		// Reserve the first two inner rows for the panel heading.
		bodyLines := strings.Split(body, "\n")
		body = strings.Join(bodyLines[:min(len(bodyLines), max(1, height-2))], "\n")
		style = style.Height(max(1, height-2))
	}
	return style.Render(body)
}

func (m *Model) header(width int) string {
	state := "○ Заблокировано"
	if m.store != nil {
		state = "● Хранилище открыто"
	}
	if m.dirty {
		state = "● Не сохранено"
	}
	if m.screen == "busy" {
		state = "◌ Обрабатываем…"
	}
	title := accent.Render("SSH MANAGER")
	if width >= 50 {
		gap := max(1, width-lipgloss.Width(title)-lipgloss.Width(state))
		title += strings.Repeat(" ", gap) + muted.Render(state)
	}
	return fitLine(title, width) + "\n" + muted.Render(fitLine(clean(m.path), width))
}

func (m *Model) statusView(width int) string {
	if m.status == "" {
		return muted.Render(fitLine("Готово", width))
	}
	text := "✓ " + clean(m.status)
	style := muted
	if m.isError {
		text = "! " + clean(m.status)
		style = danger
	}
	return style.Render(fitLine(text, width))
}

func (m *Model) frame(content string) string {
	width := max(1, m.width-4)
	body := m.header(width) + "\n\n" + content + "\n" + m.statusView(width)
	return lipgloss.NewStyle().Padding(1, 2).Render(body)
}

func (m *Model) dialogView(content string) string {
	view := m.frame(panel(m.screenTitle(), content, m.width-4, 0))
	if lipgloss.Height(view) <= m.height {
		return view
	}
	// Remove spacing before sacrificing any fields or selected objects when
	// the terminal is short. Input state is unaffected by the compact layout.
	var lines []string
	for _, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(ansi.Strip(line)) != "" {
			lines = append(lines, line)
		}
	}
	return m.frame(panel(m.screenTitle(), strings.Join(lines, "\n"), m.width-4, 0))
}

func (m *Model) smallView() string {
	minimum := "Минимум 32 × 16"
	if m.screen == "catalog" {
		minimum = "Минимум 32 × 12"
	}
	lines := []string{"SSH MANAGER", "Увеличьте окно терминала", minimum, "Ctrl+C — выход"}
	for i := range lines {
		lines[i] = fitLine(lines[i], m.width)
	}
	return strings.Join(lines[:min(len(lines), max(0, m.height))], "\n")
}

func (m *Model) screenTitle() string {
	switch m.screen {
	case "locked":
		if m.create {
			return "Создание зашифрованного хранилища"
		}
		return "Разблокировка хранилища"
	case "busy":
		return "Хранилище"
	case "files":
		if m.browser != nil && m.browser.directoryMode {
			return "Выберите папку назначения"
		}
		if m.form != nil && m.form.purpose == "credential" {
			return "Выберите файл ключа"
		}
		return "Выберите файл хранилища"
	case "references":
		if m.referencePicker != nil {
			return m.referencePicker.title
		}
		return "Выбор назначения"
	case "key-source":
		return "Импорт ключа"
	case "paste-key":
		return "Вставка ключа"
	case "conflicts":
		return "Разрешение конфликтов"
	case "confirm":
		return "Подтверждение"
	case "credentials":
		return "Профиль подключения"
	case "folders":
		return "Фильтр папок"
	}
	if m.form != nil {
		switch m.form.purpose {
		case "connection":
			return "Соединение"
		case "credential":
			return "Профиль аутентификации"
		case "folder":
			return "Папка"
		case "password":
			return "Смена главного пароля"
		case "export":
			return "Экспорт хранилища"
		case "merge":
			return "Объединение копии"
		}
	}
	return "SSH Manager"
}

func (m *Model) catalogView() string {
	width := m.width - 4
	if m.height < 18 {
		return m.compactCatalogView()
	}
	labels := []string{"Соединения", "Креды", "Папки"}
	counts := []int{len(m.doc.Connections), len(m.doc.Credentials), len(m.doc.Folders)}
	var tabs []string
	for i, label := range labels {
		text := fmt.Sprintf("%s %d", label, counts[i])
		if width < 55 {
			text = label
		}
		if i == m.tab {
			tabs = append(tabs, selectedStyle.Padding(0, 1).Render("‹ "+text+" ›"))
		} else {
			tabs = append(tabs, tabStyle.Inherit(muted).Render(text))
		}
	}
	tabsView := strings.Join(tabs, " ")
	if lipgloss.Width(tabsView) > width {
		tabsView = accent.Render("‹ " + labels[m.tab] + " ›")
	}
	search := "Поиск: /"
	if m.searching {
		input := m.search
		input.Width = max(1, width-8)
		search = "Поиск: " + input.View()
	} else if m.search.Value() != "" {
		search = "Поиск: " + clean(m.search.Value())
	}
	folder := "Все папки"
	if m.folderID != "" {
		folder = m.folderName(m.folderID)
	}
	if width >= 70 {
		searchWidth := width / 2
		search = fitLine(search, searchWidth) + strings.Repeat(" ", max(1, width-searchWidth-lipgloss.Width(folder))) + muted.Render(fitLine(folder, searchWidth))
	}
	help := m.catalogHelp(width)
	// Frame: padding (2), header (2), gaps (2), tabs/search (3),
	// footer gap (1), help and status (1).
	height := max(5, m.height-11-lipgloss.Height(help))
	rows := m.rows()
	title := fmt.Sprintf("%s · %d", labels[m.tab], len(rows))
	var content string
	switch {
	case width >= 92:
		listWidth := (width - 1) * 55 / 100
		detailWidth := width - listWidth - 1
		list := panel(title, m.catalogRows(rows, listWidth-4, height-4), listWidth, height)
		detail := panel("Подробности", m.details(rows, detailWidth-4), detailWidth, height)
		content = lipgloss.JoinHorizontal(lipgloss.Top, list, " ", detail)
	case height >= 19:
		detailHeight := min(14, height-6)
		listHeight := height - detailHeight - 1
		content = panel(title, m.catalogRows(rows, width-4, listHeight-4), width, listHeight) + "\n" + panel("Подробности", m.details(rows, width-4), width, detailHeight)
	default:
		content = panel(title, m.catalogRows(rows, width-4, height-4), width, height)
	}
	return m.frame(fitLine(tabsView, width) + "\n" + fitLine(search, width) + "\n\n" + content + "\n" + help)
}

func (m *Model) catalogHelp(width int) string {
	if width < 65 {
		return muted.Render(fitLine("←/→ каталог · ↑/↓ выбор · / поиск", width) + "\n" + fitLine("Enter открыть · пробел свернуть", width) + "\n" + fitLine("e изменить · d удалить · q выход", width))
	}
	return muted.Render(fitLine("←/→ каталог · ↑/↓ выбор · / поиск · f папка · n создать · e изменить · d удалить", width) + "\n" + fitLine("Enter открыть · пробел свернуть · a профиль · l блокировка · P пароль · q выход", width) + "\n" + fitLine("S сохранить · E экспорт · M объединить · R переоткрыть", width))
}

func (m *Model) catalogRows(rows []row, width, limit int) string {
	if len(rows) == 0 {
		if m.search.Value() != "" || m.folderID != "" {
			return muted.Render("Нет совпадений.\nИзмените поиск или фильтр.")
		}
		return muted.Render("Пока пусто.\nn — создать объект;\nсначала добавьте креды.")
	}
	limit = max(1, limit)
	start := max(0, m.selected-limit+1)
	var lines []string
	for i := start; i < len(rows) && i < start+limit; i++ {
		r := rows[i]
		name := m.treeName(r)
		detail := clean(r.detail)
		if m.tab == 1 {
			if c, ok := m.doc.Credential(r.id); ok {
				detail = clean(c.Username) + " · " + authLabel(c.Kind)
			}
		}
		nameWidth := max(10, width*45/100)
		text := "  " + name
		if width >= 40 {
			text = "  " + fitLine(name, nameWidth) + strings.Repeat(" ", max(1, nameWidth-lipgloss.Width(name)+2)) + detail
		}
		if i == m.selected {
			text = "› " + strings.TrimPrefix(text, "  ")
			lines = append(lines, selectedLine(text, width))
		} else {
			lines = append(lines, fitLine(text, width))
		}
	}
	return strings.Join(lines, "\n")
}

func (m *Model) details(rows []row, width int) string {
	if len(rows) == 0 || m.selected < 0 || m.selected >= len(rows) {
		return muted.Render("Выберите объект в списке")
	}
	r := rows[m.selected]
	lines := []string{accent.Render(fitLine(clean(r.name), width)), ""}
	add := func(label, value string) {
		if value == "" {
			value = "—"
		}
		lines = append(lines, muted.Render(label+"  ")+clean(value))
	}
	tab := m.tab
	if m.isFolder(r) {
		tab = 2
	}
	switch tab {
	case 0:
		for _, c := range m.doc.Connections {
			if c.ID != r.id {
				continue
			}
			add("Адрес", c.Host)
			add("Порт", strconv.Itoa(c.Port))
			add("Папка", m.folderName(c.FolderID))
			ids := m.doc.EffectiveCredentials(c)
			profile := m.credentialNames(ids)
			if profile == "" {
				profile = "Не назначен"
			}
			if c.DefaultCredentialID != "" {
				profile = m.credentialNames([]string{c.DefaultCredentialID})
			}
			add("Профиль", profile)
			if len(ids) == 1 || c.DefaultCredentialID != "" {
				id := c.DefaultCredentialID
				if id == "" {
					id = ids[0]
				}
				if cred, ok := m.doc.Credential(id); ok {
					add("Пользователь", cred.Username)
					add("Вход", authLabel(cred.Kind))
				}
			}
			add("Теги", c.Tags)
			if c.Notes != "" {
				add("Заметки", c.Notes)
			}
			if len(c.CredentialIDs) == 0 && len(ids) > 0 {
				lines = append(lines, "", muted.Render("Профиль унаследован от папки"))
			}
			break
		}
	case 1:
		if c, ok := m.doc.Credential(r.id); ok {
			add("Пользователь", c.Username)
			add("Вход", authLabel(c.Kind))
			if c.Kind == "local-key" {
				add("Файл", c.KeyPath)
			}
			if c.Kind == "stored-key" {
				add("Ключ", "В хранилище · скрыт")
			}
			if c.Password != "" {
				add("Пароль", "••••••••")
			}
			if c.Passphrase != "" {
				add("Парольная фраза", "••••••••")
			}
			used := 0
			for _, conn := range m.doc.Connections {
				for _, id := range m.doc.EffectiveCredentials(conn) {
					if id == c.ID {
						used++
						break
					}
				}
			}
			add("Соединений", strconv.Itoa(used))
		}
	case 2:
		for _, f := range m.doc.Folders {
			if f.ID != r.id {
				continue
			}
			add("Родитель", m.folderName(f.ParentID))
			profiles := m.credentialNames(f.CredentialIDs)
			if len(f.CredentialIDs) == 0 {
				profiles = "Наследовать от родителя"
			}
			add("Креды", profiles)
			count := 0
			for _, c := range m.doc.Connections {
				if m.inFolder(c.FolderID, f.ID) {
					count++
				}
			}
			add("Соединений", strconv.Itoa(count))
			break
		}
	}
	return strings.Join(lines, "\n")
}

// Short windows keep the selected object and primary actions on screen.
func (m *Model) compactCatalogView() string {
	width := m.width - 4
	labels := []string{"Соединения", "Креды", "Папки"}
	query := " / поиск"
	if m.searching {
		input := m.search
		input.Width = max(1, width-8)
		query = "Поиск: " + input.View()
	} else if m.search.Value() != "" {
		query = "Поиск: " + clean(m.search.Value())
	}
	content := accent.Render(fitLine("‹ "+labels[m.tab]+" ›", width)) + "\n" + fitLine(query, width) + "\n" + m.catalogRows(m.rows(), width, max(1, m.height-8)) + "\n" + muted.Render(fitLine("Enter открыть · пробел свернуть · q выход", width))
	return lipgloss.NewStyle().Padding(1, 2).Render(content + "\n" + m.statusView(width))
}
