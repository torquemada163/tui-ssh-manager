package ui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/torquemada163/tui-ssh-manager/internal/sshclient"
)

const maxKeyBytes = 1 << 20

var authKinds = []string{"agent", "local-key", "stored-key", "password"}

func authLabel(kind string) string {
	switch kind {
	case "agent":
		return "SSH-agent и стандартные ключи"
	case "local-key":
		return "Локальный ключ"
	case "stored-key":
		return "Ключ в хранилище"
	case "password":
		return "Пароль"
	}
	return "Выберите тип"
}
func isKeyKind(kind string) bool { return kind == "local-key" || kind == "stored-key" }

func (f *form) visibleFields() []int {
	var result []int
	for i := range f.fields {
		if f.purpose == "credential" && (i == 3 || i == 5) && !isKeyKind(f.fields[2].input.Value()) {
			continue
		}
		result = append(result, i)
	}
	return result
}

func (m *Model) cycleAuth(forward bool) {
	f := m.form
	kind := f.fields[2].input.Value()
	index := 0
	for i, v := range authKinds {
		if v == kind {
			index = i
		}
	}
	delta := -1
	if forward {
		delta = 1
	}
	next := authKinds[(index+delta+len(authKinds))%len(authKinds)]
	f.fields[2].input.SetValue(next)
	if !isKeyKind(next) || next == "local-key" && f.keyDraft != "" {
		f.keyDraft = ""
		f.fields[3].input.SetValue("")
	}
	m.setStatus("", false)
}

func (m *Model) keyFieldView() string {
	f := m.form
	if f.keyDraft != "" {
		return "Вставленный ключ · содержимое скрыто · Enter заменить"
	}
	if path := f.fields[3].input.Value(); path != "" {
		return clean(path) + " · Enter заменить"
	}
	if f.fields[2].input.Value() == "stored-key" && f.id != "" {
		if c, ok := m.doc.Credential(f.id); ok && c.PrivateKey != "" {
			return "Ключ уже в хранилище · Enter заменить"
		}
	}
	return "[ Выбрать ключ… ] · Enter"
}

type fileEntry struct {
	name, path         string
	directory, regular bool
	unavailable        bool
}
type fileBrowser struct {
	directory     string
	entries       []fileEntry
	selected      int
	field         int
	directoryMode bool
}

func readDirectory(directory string) ([]fileEntry, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	var result []fileEntry
	if parent := filepath.Dir(directory); parent != directory {
		result = append(result, fileEntry{name: "..", path: parent, directory: true})
	}
	var children []fileEntry
	for _, entry := range entries {
		path := filepath.Join(directory, entry.Name())
		info, err := os.Stat(path)
		child := fileEntry{name: entry.Name(), path: path, unavailable: err != nil}
		if err == nil {
			child.directory = info.IsDir()
			child.regular = info.Mode().IsRegular()
		}
		children = append(children, child)
	}
	sort.Slice(children, func(i, j int) bool {
		if children[i].directory != children[j].directory {
			return children[i].directory
		}
		return strings.ToLower(children[i].name) < strings.ToLower(children[j].name)
	})
	return append(result, children...), nil
}

func (m *Model) openBrowser() {
	m.openFileBrowser(3, false)
}

func (b *fileBrowser) filterEntries(entries []fileEntry) []fileEntry {
	if !b.directoryMode {
		return entries
	}
	var directories []fileEntry
	for _, entry := range entries {
		if entry.directory {
			directories = append(directories, entry)
		}
	}
	return directories
}

func (m *Model) openFileBrowser(field int, directoryMode bool) {
	home, err := os.UserHomeDir()
	if err != nil {
		m.setStatus("Не удалось найти домашнюю папку", true)
		return
	}
	directory := filepath.Join(home, ".ssh")
	if m.form.purpose != "credential" {
		directory = filepath.Dir(m.path)
	}
	if info, err := os.Stat(directory); err != nil || !info.IsDir() {
		directory = home
	}
	selectedPath := ""
	if path := m.form.fields[field].input.Value(); path != "" {
		if full, err := sshclient.ExpandPath(path); err == nil {
			if info, err := os.Stat(full); err == nil {
				if info.IsDir() {
					directory = full
				} else {
					directory = filepath.Dir(full)
					selectedPath = full
				}
			}
		}
	}
	entries, err := readDirectory(directory)
	if err != nil {
		m.setStatus("Не удалось открыть папку: "+err.Error(), true)
		return
	}
	m.browser = &fileBrowser{directory: directory, field: field, directoryMode: directoryMode}
	m.browser.entries = m.browser.filterEntries(entries)
	for i, entry := range m.browser.entries {
		if entry.path == selectedPath {
			m.browser.selected = i
		}
	}
	m.screen = "files"
	m.setStatus("", false)
}

func (m *Model) browseInto(path string) {
	entries, err := readDirectory(path)
	if err != nil {
		m.setStatus("Не удалось открыть папку: "+err.Error(), true)
		return
	}
	previous := m.browser.directory
	m.browser.directory = path
	m.browser.entries = m.browser.filterEntries(entries)
	m.browser.selected = 0
	// On ascent, retain the highlight on the directory we just left.
	for i, entry := range m.browser.entries {
		if entry.path == previous {
			m.browser.selected = i
		}
	}
	m.setStatus("", false)
}

func (m *Model) updateBrowser(msg tea.KeyMsg) tea.Cmd {
	b := m.browser
	switch msg.String() {
	case "esc":
		m.browser = nil
		m.screen = "form"
		return nil
	case "ctrl+s":
		if b.directoryMode {
			m.form.fields[b.field].input.SetValue(b.directory)
			m.browser = nil
			m.screen = "form"
			m.setStatus("Папка назначения выбрана", false)
		}
	case "up", "k":
		if b.selected > 0 {
			b.selected--
		}
	case "down", "j":
		if b.selected < len(b.entries)-1 {
			b.selected++
		}
	case "home":
		b.selected = 0
	case "end":
		if len(b.entries) > 0 {
			b.selected = len(b.entries) - 1
		}
	case "left", "backspace":
		m.browseInto(filepath.Dir(b.directory))
	case "h", "~":
		if home, err := os.UserHomeDir(); err == nil {
			m.browseInto(home)
		}
	case "enter", "right":
		if len(b.entries) == 0 {
			return nil
		}
		entry := b.entries[b.selected]
		if entry.unavailable {
			m.setStatus("Файл или папка недоступны", true)
			return nil
		}
		if entry.directory {
			m.browseInto(entry.path)
		} else if msg.String() == "enter" {
			if !entry.regular {
				m.setStatus("Выберите обычный файл", true)
				return nil
			}
			path := entry.path
			if m.form.purpose == "credential" && m.form.fields[2].input.Value() == "local-key" {
				if home, err := os.UserHomeDir(); err == nil {
					if relative, err := filepath.Rel(home, path); err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
						path = filepath.Join("~", relative)
					}
				}
			}
			m.form.fields[b.field].input.SetValue(path)
			if m.form.purpose == "credential" {
				m.form.keyDraft = ""
			}
			m.browser = nil
			m.screen = "form"
			if m.form.purpose == "credential" {
				m.setStatus("Файл ключа выбран", false)
			} else {
				m.setStatus("Файл хранилища выбран", false)
			}
		}
	}
	return nil
}

func (m *Model) browserView() string {
	b := m.browser
	var view strings.Builder
	view.WriteString(clean(b.directory) + "\n" + muted.Render("Скрытые файлы и папки отображаются") + "\n\n")
	limit := m.height - 18
	if limit < 1 {
		limit = 1
	}
	start := 0
	if b.selected >= limit {
		start = b.selected - limit + 1
	}
	for i := start; i < len(b.entries) && i < start+limit; i++ {
		entry := b.entries[i]
		name := clean(entry.name)
		if entry.directory {
			name += "/"
		}
		if entry.unavailable {
			name += " (недоступно)"
		}
		if i == b.selected {
			view.WriteString(selectedLine("› "+name, m.width-8) + "\n")
		} else {
			view.WriteString("  " + name + "\n")
		}
	}
	if len(b.entries) == 0 {
		view.WriteString("Папка пуста\n")
	}
	view.WriteString("\n" + muted.Render("↑/↓ выбрать · Enter открыть/выбрать · ←/Backspace наверх · h домой · Esc отменить"))
	if b.directoryMode {
		view.WriteString("\n" + muted.Render("Ctrl+S использовать текущую папку"))
	}
	return view.String()
}

func (m *Model) updateKeySource(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "esc":
		m.screen = "form"
	case "left", "right", "up", "down":
		m.keySource = 1 - m.keySource
	case "enter":
		if m.keySource == 0 {
			m.openBrowser()
		} else {
			m.openKeyPaste()
		}
	case "ctrl+v":
		m.openKeyPaste()
		return m.readClipboard()
	}
	return nil
}

func (m *Model) openKeyPaste() {
	m.screen = "paste-key"
	m.pasteBuffer = ""
	m.pasteReading = false
	m.clipboardSession++
	m.setStatus("", false)
}

func normalizeKey(value string) string {
	return strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(value, "\r\n", "\n"), "\r", "\n")) + "\n"
}

func (m *Model) acceptPastedKey(value string) {
	if len(value) >= maxKeyBytes {
		m.setStatus("Вставленный ключ слишком большой", true)
		return
	}
	if strings.TrimSpace(value) == "" {
		m.setStatus("Буфер обмена пуст", true)
		return
	}
	m.pasteBuffer = normalizeKey(value)
	m.setStatus("Ключ получен; Enter — использовать", false)
}

func (m *Model) updateKeyPaste(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "esc":
		m.pasteBuffer = ""
		m.pasteReading = false
		m.clipboardSession++
		m.screen = "form"
	case "ctrl+u":
		m.pasteBuffer = ""
		m.pasteReading = false
		m.clipboardSession++
		m.setStatus("", false)
	case "ctrl+v":
		return m.readClipboard()
	case "enter":
		if m.pasteReading {
			m.setStatus("Дождитесь чтения буфера обмена", true)
			return nil
		}
		if !strings.HasPrefix(m.pasteBuffer, "-----BEGIN ") || !strings.Contains(m.pasteBuffer, "PRIVATE KEY-----") || !strings.Contains(m.pasteBuffer, "-----END ") {
			m.setStatus("Вставьте весь приватный ключ, включая BEGIN и END", true)
			return nil
		}
		m.form.keyDraft = m.pasteBuffer
		m.form.fields[3].input.SetValue("")
		m.pasteBuffer = ""
		m.screen = "form"
		m.clipboardSession++
		m.setStatus("Ключ вставлен; при необходимости укажите парольную фразу", false)
	default:
		if msg.Type == tea.KeyRunes && msg.Paste {
			m.pasteReading = false
			m.clipboardSession++
			m.acceptPastedKey(string(msg.Runes))
		}
	}
	return nil
}

type clipboardMsg struct {
	session  int
	contents string
	err      error
}

func (m *Model) readClipboard() tea.Cmd {
	m.clipboardSession++
	session := m.clipboardSession
	m.pasteReading = true
	m.setStatus("Читаем буфер обмена…", false)
	reader := m.clipboardReader
	if reader == nil {
		reader = systemClipboard
	}
	return func() tea.Msg { contents, err := reader(); return clipboardMsg{session, contents, err} }
}

// Clipboard reads are explicit user actions. No key is sent to a shell, log or
// temporary file. Terminal paste remains available on hosts without a desktop.
func systemClipboard() (string, error) {
	var candidates [][]string
	if runtime.GOOS == "darwin" {
		candidates = [][]string{{"pbpaste"}}
	} else {
		if os.Getenv("WAYLAND_DISPLAY") != "" {
			candidates = append(candidates, []string{"wl-paste", "--no-newline"})
		}
		if os.Getenv("DISPLAY") != "" {
			candidates = append(candidates, []string{"xclip", "-out", "-selection", "clipboard"}, []string{"xsel", "--output", "--clipboard"})
		}
	}
	for _, args := range candidates {
		path, err := exec.LookPath(args[0])
		if err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		cmd := exec.CommandContext(ctx, path, args[1:]...)
		cmd.Stderr = io.Discard
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			cancel()
			continue
		}
		if err = cmd.Start(); err != nil {
			cancel()
			continue
		}
		raw, readErr := io.ReadAll(io.LimitReader(stdout, maxKeyBytes+1))
		if len(raw) >= maxKeyBytes {
			_ = cmd.Process.Kill()
		}
		_ = stdout.Close()
		waitErr := cmd.Wait()
		cancel()
		if len(raw) >= maxKeyBytes {
			for i := range raw {
				raw[i] = 0
			}
			return "", errors.New("Ключ в буфере обмена слишком большой")
		}
		if readErr != nil || waitErr != nil {
			for i := range raw {
				raw[i] = 0
			}
			continue
		}
		value := string(raw)
		for i := range raw {
			raw[i] = 0
		}
		return value, nil
	}
	return "", fmt.Errorf("Системный буфер недоступен. Вставьте ключ сочетанием вашего терминала (⌘V / Ctrl+Shift+V)")
}
