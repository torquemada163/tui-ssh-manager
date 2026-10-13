package ui

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/torquemada163/tui-ssh-manager/internal/domain"
	"github.com/torquemada163/tui-ssh-manager/internal/sshclient"
	"github.com/torquemada163/tui-ssh-manager/internal/vault"
)

type field struct {
	label string
	input textinput.Model
}
type form struct {
	purpose    string
	id         string
	fields     []field
	focus      int
	keyDraft   string
	references map[int][]string
}
type row struct{ id, name, detail string }
type unlockedMsg struct {
	store *vault.Store
	doc   domain.Document
	err   error
}
type savedMsg struct {
	doc     domain.Document
	err     error
	message string
}
type sshDoneMsg struct {
	err   error
	ended time.Time
}
type noticeMsg struct {
	err     error
	message string
}

type importedMsg struct {
	doc domain.Document
	err error
}

type Model struct {
	path             string
	store            *vault.Store
	doc              domain.Document
	runner           *sshclient.Runner
	width, height    int
	tab, selected    int
	screen           string
	form             *form
	status           string
	isError, dirty   bool
	search           textinput.Model
	searching        bool
	folderID         string
	choices          []row
	choice           int
	connection       domain.Connection
	confirmAction    string
	create           bool
	lastAction       time.Time
	idle             time.Duration
	conflictRemote   domain.Document
	conflictIDs      []string
	decisions        map[string]string
	conflictImport   bool
	conflictPos      int
	browser          *fileBrowser
	keySource        int
	pasteBuffer      string
	pasteReading     bool
	clipboardSession int
	clipboardReader  func() (string, error)
	referencePicker  *referencePicker
}

func New(path string, runner *sshclient.Runner, idle time.Duration) *Model {
	search := textinput.New()
	search.Placeholder = "Имя, адрес или тег"
	search.CharLimit = 256
	m := &Model{path: path, runner: runner, width: 100, height: 30, search: search, idle: idle, lastAction: time.Now()}
	m.locked()
	return m
}

func (m *Model) Close() {
	if m.store != nil {
		m.store.Close()
		m.store = nil
	}
	m.doc = domain.Document{}
	m.form = nil
	m.conflictRemote = domain.Document{}
	m.conflictIDs = nil
	m.decisions = nil
	m.connection = domain.Connection{}
	m.choices = nil
	m.browser = nil
	m.pasteBuffer = ""
	m.pasteReading = false
	m.clipboardSession++
	m.referencePicker = nil
}
func (m *Model) Init() tea.Cmd {
	return tea.Batch(textinput.Blink, tea.Tick(time.Second*15, func(t time.Time) tea.Msg { return t }))
}

func makeForm(purpose, id string, labels, values []string, secrets map[int]bool) *form {
	f := &form{purpose: purpose, id: id, references: map[int][]string{}}
	for i, label := range labels {
		input := textinput.New()
		input.CharLimit = 4096
		input.Width = 65
		if i < len(values) {
			input.SetValue(values[i])
		}
		if secrets[i] {
			input.EchoMode = textinput.EchoPassword
			input.EchoCharacter = '•'
		}
		f.fields = append(f.fields, field{label: label, input: input})
	}
	f.fields[0].input.Focus()
	return f
}

func (m *Model) locked() {
	m.Close()
	m.screen = "locked"
	m.dirty = false
	_, err := os.Stat(m.path)
	m.create = os.IsNotExist(err)
	labels := []string{"Главный пароль"}
	if m.create {
		labels = append(labels, "Повторите пароль (минимум 10 символов)")
	}
	m.form = makeForm("unlock", "", labels, nil, map[int]bool{0: true, 1: true})
	if err != nil && !m.create {
		m.setStatus(err.Error(), true)
	}
}

func (m *Model) setStatus(s string, isError bool) { m.status = s; m.isError = isError }
func clean(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r != 127 && !(r >= 128 && r <= 159) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case clipboardMsg:
		if m.screen != "paste-key" || msg.session != m.clipboardSession {
			return m, nil
		}
		m.pasteReading = false
		if msg.err != nil {
			m.setStatus(msg.err.Error(), true)
		} else {
			m.acceptPastedKey(msg.contents)
		}
		return m, nil
	case time.Time:
		if m.screen == "catalog" && !m.dirty && m.idle > 0 && time.Since(m.lastAction) >= m.idle {
			m.locked()
			m.setStatus("Хранилище заблокировано по таймауту", false)
		}
		return m, tea.Tick(time.Second*15, func(t time.Time) tea.Msg { return t })
	case unlockedMsg:
		if msg.err != nil {
			m.locked()
			m.setStatus(msg.err.Error(), true)
			return m, textinput.Blink
		}
		m.store, m.doc = msg.store, msg.doc
		m.form = nil
		m.screen = "catalog"
		m.lastAction = time.Now()
		m.setStatus("Хранилище открыто", false)
		return m, nil
	case savedMsg:
		m.doc = msg.doc
		m.form = nil
		m.screen = "catalog"
		m.dirty = msg.err != nil
		if msg.err != nil {
			var conflict *vault.Conflict
			if errors.As(msg.err, &conflict) {
				remote, err := m.store.Preview(m.doc)
				if errors.As(err, &conflict) {
					m.beginConflict(remote, conflict, false)
					return m, nil
				}
			}
			m.setStatus(msg.err.Error()+" · S повторить · E экспорт · R переоткрыть", true)
		} else {
			m.setStatus(msg.message, false)
		}
		m.clamp()
		return m, nil
	case noticeMsg:
		m.screen = "catalog"
		m.form = nil
		if msg.err != nil {
			m.setStatus(msg.err.Error(), true)
		} else {
			m.setStatus(msg.message, false)
		}
		return m, nil
	case importedMsg:
		m.screen = "catalog"
		m.form = nil
		if msg.err != nil {
			m.setStatus(msg.err.Error(), true)
			return m, nil
		}
		doc, err := vault.MergeCopy(m.doc, msg.doc, nil)
		var conflict *vault.Conflict
		if errors.As(err, &conflict) {
			m.beginConflict(msg.doc, conflict, true)
			return m, nil
		}
		if err != nil {
			m.setStatus(err.Error(), true)
			return m, nil
		}
		return m, m.save(doc)
	case sshDoneMsg:
		m.screen = "catalog"
		if m.idle > 0 && msg.ended.Sub(m.lastAction) >= m.idle {
			m.locked()
			m.setStatus("SSH завершён. Разблокируйте хранилище", false)
			return m, textinput.Blink
		}
		doc, err := m.store.Refresh(m.doc)
		if err != nil {
			m.setStatus(err.Error(), true)
		} else {
			m.doc = doc
			if msg.err != nil {
				m.setStatus("SSH: "+msg.err.Error(), true)
			} else {
				m.setStatus("SSH завершён", false)
			}
		}
		m.lastAction = time.Now()
		m.clamp()
		return m, nil
	case tea.KeyMsg:
		if m.screen == "busy" || m.screen == "ssh" {
			return m, nil
		}
		m.lastAction = time.Now()
		if msg.String() == "ctrl+c" {
			return m, m.quit()
		}
		if m.screen == "locked" || m.screen == "form" {
			return m, m.updateForm(msg)
		}
		if m.screen == "files" {
			return m, m.updateBrowser(msg)
		}
		if m.screen == "references" {
			return m, m.updateReferencePicker(msg)
		}
		if m.screen == "key-source" {
			return m, m.updateKeySource(msg)
		}
		if m.screen == "paste-key" {
			return m, m.updateKeyPaste(msg)
		}
		if m.screen == "confirm" {
			switch msg.String() {
			case "esc", "n":
				m.screen = "catalog"
			case "y", "enter":
				return m, m.confirm()
			}
			return m, nil
		}
		if m.screen == "credentials" || m.screen == "folders" {
			return m, m.updatePicker(msg)
		}
		if m.screen == "conflicts" {
			return m, m.updateConflicts(msg)
		}
		if m.searching {
			if msg.String() == "enter" || msg.String() == "esc" {
				m.searching = false
				m.search.Blur()
				return m, nil
			}
			var cmd tea.Cmd
			m.search, cmd = m.search.Update(msg)
			m.selected = 0
			return m, cmd
		}
		switch msg.String() {
		case "q":
			return m, m.quit()
		case "tab", "right":
			m.tab = (m.tab + 1) % 3
			m.selected = 0
			m.search.SetValue("")
		case "shift+tab", "left":
			m.tab = (m.tab + 2) % 3
			m.selected = 0
			m.search.SetValue("")
		case "up", "k":
			m.selected--
			m.clamp()
		case "down", "j":
			m.selected++
			m.clamp()
		case "home":
			m.selected = 0
		case "end":
			m.selected = len(m.rows()) - 1
			m.clamp()
		case "/":
			m.searching = true
			m.search.Focus()
			return m, textinput.Blink
		case "esc":
			m.search.SetValue("")
			m.folderID = ""
			m.selected = 0
		case "n":
			m.edit(false)
		case "e":
			m.edit(true)
		case "d":
			if len(m.rows()) > 0 {
				m.confirmAction = "delete"
				m.screen = "confirm"
			}
		case "enter":
			if m.tab == 0 {
				return m, m.connect(false)
			} else {
				m.edit(true)
			}
		case "a":
			if m.tab == 0 {
				return m, m.connect(true)
			}
		case "f":
			m.chooseFolder()
		case "l":
			if m.dirty {
				m.setStatus("Сначала сохраните или экспортируйте изменения", true)
			} else {
				m.locked()
				return m, textinput.Blink
			}
		case "S", "ctrl+s":
			return m, m.save(m.doc)
		case "R":
			if m.dirty {
				m.confirmAction = "reload"
				m.screen = "confirm"
			} else {
				m.locked()
				return m, textinput.Blink
			}
		case "E":
			m.form = makeForm("export", "", []string{"Папка назначения (Enter — выбрать)", "Имя нового файла"}, []string{filepath.Dir(m.path), filepath.Base(m.path) + ".export-" + time.Now().Format("20060102-150405")}, nil)
			m.screen = "form"
		case "P":
			m.form = makeForm("password", "", []string{"Новый главный пароль", "Повторите новый пароль"}, nil, map[int]bool{0: true, 1: true})
			m.screen = "form"
		case "M":
			m.form = makeForm("merge", "", []string{"Файл конфликтной копии (Enter — выбрать)", "Главный пароль этой копии"}, nil, map[int]bool{1: true})
			m.screen = "form"
		}
		return m, nil
	}
	if m.form != nil {
		var cmd tea.Cmd
		i := m.form.focus
		m.form.fields[i].input, cmd = m.form.fields[i].input.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m *Model) quit() tea.Cmd {
	if m.dirty {
		m.confirmAction = "quit"
		m.screen = "confirm"
		return nil
	}
	m.Close()
	return tea.Quit
}

func (m *Model) rows() []row {
	var rows []row
	switch m.tab {
	case 0:
		for _, c := range m.doc.Connections {
			if m.folderID != "" && !m.inFolder(c.FolderID, m.folderID) {
				continue
			}
			rows = append(rows, row{c.ID, c.Name, fmt.Sprintf("%s:%d · %s · %s", c.Host, c.Port, m.folderName(c.FolderID), c.Tags)})
		}
	case 1:
		for _, c := range m.doc.Credentials {
			rows = append(rows, row{c.ID, c.Name, c.Username + " · " + c.Kind})
		}
	case 2:
		for _, f := range m.doc.Folders {
			rows = append(rows, row{f.ID, f.Name, m.folderName(f.ParentID)})
		}
	}
	q := strings.ToLower(m.search.Value())
	var filtered []row
	for _, r := range rows {
		if strings.Contains(strings.ToLower(r.name+" "+r.detail), q) {
			filtered = append(filtered, r)
		}
	}
	sort.Slice(filtered, func(i, j int) bool { return strings.ToLower(filtered[i].name) < strings.ToLower(filtered[j].name) })
	return filtered
}

func (m *Model) clamp() {
	n := len(m.rows())
	if m.selected >= n {
		m.selected = n - 1
	}
	if m.selected < 0 {
		m.selected = 0
	}
}
func (m *Model) folderName(id string) string {
	if id == "" {
		return "—"
	}
	for _, f := range m.doc.Folders {
		if f.ID == id {
			return f.Name
		}
	}
	return "?"
}
func (m *Model) inFolder(id, parent string) bool {
	for id != "" {
		if id == parent {
			return true
		}
		next := ""
		for _, f := range m.doc.Folders {
			if f.ID == id {
				next = f.ParentID
				break
			}
		}
		id = next
	}
	return false
}
func (m *Model) credentialNames(ids []string) string {
	var names []string
	for _, id := range ids {
		if c, ok := m.doc.Credential(id); ok {
			names = append(names, c.Name)
		}
	}
	return strings.Join(names, ", ")
}

func (m *Model) edit(existing bool) {
	var id string
	if existing {
		rows := m.rows()
		if len(rows) == 0 {
			return
		}
		id = rows[m.selected].id
	}
	switch m.tab {
	case 0:
		c := domain.Connection{Port: 22, FolderID: m.folderID}
		for _, v := range m.doc.Connections {
			if v.ID == id {
				c = v
			}
		}
		m.form = makeForm("connection", id, []string{"Имя (необязательно; по умолчанию адрес)", "Адрес (hostname или IP)", "Порт", "Папка (Enter — выбрать)", "Креды (Enter — выбрать несколько)", "Креды по умолчанию (Enter — выбрать)", "Теги", "Заметки"}, []string{c.Name, c.Host, strconv.Itoa(c.Port), "", "", "", c.Tags, c.Notes}, nil)
		m.form.references[3] = optionalID(c.FolderID)
		m.form.references[4] = append([]string(nil), c.CredentialIDs...)
		m.form.references[5] = optionalID(c.DefaultCredentialID)
	case 1:
		c := domain.Credential{Kind: "agent"}
		for _, v := range m.doc.Credentials {
			if v.ID == id {
				c = v
			}
		}
		m.form = makeForm("credential", id, []string{"Имя (необязательно; можно оставить автоматически)", "Пользователь", "Тип аутентификации (←/→ выбрать)", "Ключ (Enter — выбрать источник)", "Пароль (необязательно для ключа)", "Парольная фраза ключа"}, []string{c.Name, c.Username, c.Kind, c.KeyPath, c.Password, c.Passphrase}, map[int]bool{4: true, 5: true})
	case 2:
		f := domain.Folder{}
		for _, v := range m.doc.Folders {
			if v.ID == id {
				f = v
			}
		}
		m.form = makeForm("folder", id, []string{"Имя (уникальное)", "Родительская папка (Enter — выбрать)", "Креды по умолчанию (Enter — выбрать несколько)"}, []string{f.Name, "", ""}, nil)
		m.form.references[1] = optionalID(f.ParentID)
		m.form.references[2] = append([]string(nil), f.CredentialIDs...)
	}
	m.screen = "form"
	m.setStatus("", false)
}

func (m *Model) updateForm(msg tea.KeyMsg) tea.Cmd {
	f := m.form
	if msg.String() == "esc" {
		if m.screen == "locked" {
			return m.quit()
		}
		m.form = nil
		m.screen = "catalog"
		return nil
	}
	if f.isReferenceField(f.focus) {
		switch msg.String() {
		case "enter", "left", "right", " ":
			m.openReferencePicker()
			return nil
		case "backspace", "delete", "ctrl+u":
			f.references[f.focus] = nil
			m.reconcileDefaultCredential()
			return nil
		}
	}
	if f.focus == 0 && (f.purpose == "merge" || f.purpose == "export") {
		if msg.String() == "enter" || msg.String() == "ctrl+b" || msg.String() == "left" || msg.String() == "right" {
			m.openFileBrowser(0, f.purpose == "export")
			return nil
		}
	}
	if f.purpose == "credential" {
		if f.focus == 2 && (msg.String() == "left" || msg.String() == "right") {
			m.cycleAuth(msg.String() == "right")
			return nil
		}
		if f.focus == 3 && isKeyKind(f.fields[2].input.Value()) {
			switch msg.String() {
			case "enter":
				if f.fields[2].input.Value() == "local-key" {
					m.openBrowser()
				} else {
					m.screen = "key-source"
					m.keySource = 0
				}
				return nil
			case "ctrl+b":
				m.openBrowser()
				return nil
			case "ctrl+v":
				if f.fields[2].input.Value() == "stored-key" {
					m.openKeyPaste()
					return m.readClipboard()
				}
				return nil
			case "backspace", "delete", "ctrl+u":
				f.fields[3].input.SetValue("")
				f.keyDraft = ""
				return nil
			}
			if msg.Type == tea.KeyRunes && msg.Paste && f.fields[2].input.Value() == "stored-key" {
				m.openKeyPaste()
				m.acceptPastedKey(string(msg.Runes))
				return nil
			}
		}
	}
	visible := f.visibleFields()
	if msg.String() == "ctrl+s" || msg.String() == "enter" && f.focus == visible[len(visible)-1] {
		return m.submit()
	}
	if msg.String() == "tab" || msg.String() == "down" || msg.String() == "enter" || msg.String() == "shift+tab" || msg.String() == "up" {
		f.fields[f.focus].input.Blur()
		delta := 1
		if msg.String() == "up" || msg.String() == "shift+tab" {
			delta = -1
		}
		pos := 0
		for i, index := range visible {
			if index == f.focus {
				pos = i
				break
			}
		}
		f.focus = visible[(pos+delta+len(visible))%len(visible)]
		f.fields[f.focus].input.Focus()
		return textinput.Blink
	}
	if f.purpose == "credential" && (f.focus == 2 || f.focus == 3) {
		return nil
	}
	if f.isReferenceField(f.focus) {
		return nil
	}
	if f.focus == 0 && (f.purpose == "merge" || f.purpose == "export") {
		return nil
	}
	var cmd tea.Cmd
	f.fields[f.focus].input, cmd = f.fields[f.focus].input.Update(msg)
	return cmd
}

func copyDoc(d domain.Document) domain.Document {
	raw, _ := json.Marshal(d)
	var out domain.Document
	_ = json.Unmarshal(raw, &out)
	for i := range raw {
		raw[i] = 0
	}
	return out
}

func (m *Model) submit() tea.Cmd {
	f := m.form
	values := make([]string, len(f.fields))
	for i, field := range f.fields {
		values[i] = field.input.Value()
	}
	problem := func(err error) tea.Cmd { m.setStatus(err.Error(), true); return nil }
	switch f.purpose {
	case "unlock":
		password := []byte(values[0])
		if m.create && values[0] != values[1] {
			return problem(errors.New("пароли не совпадают"))
		}
		if m.create && len([]rune(values[0])) < 10 {
			return problem(errors.New("главный пароль должен содержать минимум 10 символов"))
		}
		m.form = nil
		m.screen = "busy"
		create, path := m.create, m.path
		return func() tea.Msg {
			defer func() {
				for i := range password {
					password[i] = 0
				}
			}()
			var s *vault.Store
			var d domain.Document
			var err error
			if create {
				s, d, err = vault.Create(path, password)
			} else {
				s, d, err = vault.Open(path, password)
			}
			return unlockedMsg{s, d, err}
		}
	case "password":
		if values[0] != values[1] || len([]rune(values[0])) < 10 {
			return problem(errors.New("нужны два одинаковых пароля длиной от 10 символов"))
		}
		password := []byte(values[0])
		store, doc := m.store, m.doc
		m.form = nil
		m.screen = "busy"
		return func() tea.Msg {
			defer func() {
				for i := range password {
					password[i] = 0
				}
			}()
			d, err := store.ChangePassword(doc, password)
			return savedMsg{d, err, "Главный пароль изменён; старые резервные копии используют прежний пароль"}
		}
	case "export":
		if values[1] == "" || values[1] == "." || values[1] == ".." || strings.ContainsAny(values[1], "/\\") || !domain.SafeText(values[1]) {
			return problem(errors.New("Укажите имя файла без пути"))
		}
		path, err := sshclient.ExpandPath(filepath.Join(values[0], values[1]))
		if err != nil {
			return problem(err)
		}
		store, doc := m.store, m.doc
		m.screen = "busy"
		m.form = nil
		return func() tea.Msg {
			err := store.Export(path, doc)
			return noticeMsg{err, "Зашифрованная копия сохранена: " + path}
		}
	case "merge":
		if values[0] == "" {
			return problem(errors.New("Выберите файл конфликтной копии"))
		}
		path, err := sshclient.ExpandPath(values[0])
		if err != nil {
			return problem(err)
		}
		password := []byte(values[1])
		m.screen = "busy"
		m.form = nil
		return func() tea.Msg {
			defer func() {
				for i := range password {
					password[i] = 0
				}
			}()
			store, doc, err := vault.Open(path, password)
			if store != nil {
				store.Close()
			}
			return importedMsg{doc, err}
		}
	}
	d := copyDoc(m.doc)
	id := f.id
	if id == "" {
		id = domain.NewID()
	}
	switch f.purpose {
	case "connection":
		port, err := strconv.Atoi(strings.TrimSpace(values[2]))
		if err != nil {
			return problem(errors.New("порт должен быть числом"))
		}
		folder := firstID(f.references[3])
		creds := append([]string(nil), f.references[4]...)
		defaultID := firstID(f.references[5])
		c := domain.Connection{ID: id, Name: strings.TrimSpace(values[0]), Host: strings.TrimSpace(values[1]), Port: port, FolderID: folder, CredentialIDs: creds, DefaultCredentialID: defaultID, Tags: values[6], Notes: values[7]}
		if c.Name == "" {
			c.Name = c.Host
		}
		found := false
		for i, v := range d.Connections {
			if v.ID == id {
				d.Connections[i] = c
				found = true
			}
		}
		if !found {
			d.Connections = append(d.Connections, c)
		}
	case "credential":
		c := domain.Credential{ID: id, Name: strings.TrimSpace(values[0]), Username: strings.TrimSpace(values[1]), Kind: strings.TrimSpace(values[2]), Password: values[4], Passphrase: values[5]}
		if c.Name == "" {
			base := c.Username + " (" + authLabel(c.Kind) + ")"
			c.Name = base
			for n := 2; ; n++ {
				taken := false
				for _, other := range d.Credentials {
					if other.ID != id && strings.EqualFold(other.Name, c.Name) {
						taken = true
						break
					}
				}
				if !taken {
					break
				}
				c.Name = fmt.Sprintf("%s #%d", base, n)
			}
		}
		if strings.ContainsAny(c.Password+c.Passphrase, "\r\n") {
			return problem(errors.New("пароль не должен содержать перевод строки"))
		}
		if c.Kind == "local-key" {
			c.KeyPath = values[3]
		}
		if c.Kind == "stored-key" {
			for _, old := range d.Credentials {
				if old.ID == id {
					c.PrivateKey = old.PrivateKey
				}
			}
			if f.keyDraft != "" {
				c.PrivateKey = f.keyDraft
			} else if values[3] != "" {
				path, err := sshclient.ExpandPath(values[3])
				if err != nil {
					return problem(err)
				}
				keyFile, err := os.Open(path)
				if err != nil {
					return problem(err)
				}
				raw, err := io.ReadAll(io.LimitReader(keyFile, 1<<20))
				_ = keyFile.Close()
				if err != nil {
					return problem(err)
				}
				if len(raw) >= 1<<20 {
					return problem(errors.New("файл ключа слишком большой"))
				}
				c.PrivateKey = string(raw)
				for i := range raw {
					raw[i] = 0
				}
			}
			if err := sshclient.ValidatePrivateKey(c.PrivateKey, c.Passphrase); err != nil {
				return problem(err)
			}
		}
		found := false
		for i, v := range d.Credentials {
			if v.ID == id {
				d.Credentials[i] = c
				found = true
			}
		}
		if !found {
			d.Credentials = append(d.Credentials, c)
		}
	case "folder":
		name := strings.TrimSpace(values[0])
		for _, other := range d.Folders {
			if other.ID != id && strings.EqualFold(other.Name, name) {
				return problem(errors.New("имя папки уже используется"))
			}
		}
		parent := firstID(f.references[1])
		creds := append([]string(nil), f.references[2]...)
		folder := domain.Folder{ID: id, Name: name, ParentID: parent, CredentialIDs: creds}
		found := false
		for i, v := range d.Folders {
			if v.ID == id {
				d.Folders[i] = folder
				found = true
			}
		}
		if !found {
			d.Folders = append(d.Folders, folder)
		}
	}
	if err := d.Validate(); err != nil {
		return problem(err)
	}
	return m.save(d)
}

func (m *Model) save(d domain.Document) tea.Cmd {
	if err := d.Validate(); err != nil {
		m.setStatus(err.Error(), true)
		return nil
	}
	m.doc = d
	m.dirty = true
	m.screen = "busy"
	m.form = nil
	store := m.store
	return func() tea.Msg {
		doc, err := store.Save(d)
		return savedMsg{doc, err, "Изменения сохранены"}
	}
}

func (m *Model) confirm() tea.Cmd {
	m.screen = "catalog"
	switch m.confirmAction {
	case "quit":
		m.Close()
		return tea.Quit
	case "reload":
		m.locked()
		return textinput.Blink
	case "delete":
		rows := m.rows()
		if len(rows) == 0 {
			return nil
		}
		id := rows[m.selected].id
		d := copyDoc(m.doc)
		switch m.tab {
		case 0:
			for i, c := range d.Connections {
				if c.ID == id {
					d.Connections = append(d.Connections[:i], d.Connections[i+1:]...)
					break
				}
			}
		case 1:
			var dependent []string
			for _, c := range d.Connections {
				for _, ref := range d.EffectiveCredentials(c) {
					if ref == id {
						dependent = append(dependent, c.Name)
						break
					}
				}
			}
			for _, f := range d.Folders {
				for _, ref := range f.CredentialIDs {
					if ref == id {
						dependent = append(dependent, "папка "+f.Name)
						break
					}
				}
			}
			if len(dependent) > 0 {
				m.setStatus("Сначала переназначьте креды: "+strings.Join(dependent, ", "), true)
				return nil
			}
			for i, c := range d.Credentials {
				if c.ID == id {
					d.Credentials = append(d.Credentials[:i], d.Credentials[i+1:]...)
					break
				}
			}
		case 2:
			for _, c := range d.Connections {
				if c.FolderID == id {
					m.setStatus("Сначала переместите соединение "+c.Name, true)
					return nil
				}
			}
			for _, f := range d.Folders {
				if f.ParentID == id {
					m.setStatus("Сначала переместите папку "+f.Name, true)
					return nil
				}
			}
			for i, f := range d.Folders {
				if f.ID == id {
					d.Folders = append(d.Folders[:i], d.Folders[i+1:]...)
					break
				}
			}
			if m.folderID == id {
				m.folderID = ""
			}
		}
		return m.save(d)
	}
	return nil
}

func (m *Model) chooseFolder() {
	m.screen = "folders"
	m.choices = []row{{"", "Все папки", ""}}
	for _, f := range m.doc.Folders {
		m.choices = append(m.choices, row{f.ID, f.Name, m.folderName(f.ParentID)})
	}
	m.choice = 0
}

func (m *Model) connect(choose bool) tea.Cmd {
	if m.dirty {
		m.setStatus("Сначала сохраните изменения (S) или переоткройте хранилище (R)", true)
		return nil
	}
	rows := m.rows()
	if len(rows) == 0 {
		return nil
	}
	var c domain.Connection
	for _, v := range m.doc.Connections {
		if v.ID == rows[m.selected].id {
			c = v
			break
		}
	}
	ids := m.doc.EffectiveCredentials(c)
	if len(ids) == 0 {
		m.setStatus("Назначьте креды соединению или его папке", true)
		return nil
	}
	if !choose {
		if c.DefaultCredentialID != "" {
			cred, _ := m.doc.Credential(c.DefaultCredentialID)
			return m.launch(c, cred)
		}
		if len(ids) == 1 {
			cred, _ := m.doc.Credential(ids[0])
			return m.launch(c, cred)
		}
	}
	m.connection = c
	m.choices = nil
	for _, id := range ids {
		cred, _ := m.doc.Credential(id)
		m.choices = append(m.choices, row{id, cred.Name, cred.Username + " · " + cred.Kind})
	}
	m.screen = "credentials"
	m.choice = 0
	return nil
}

func (m *Model) updatePicker(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "esc":
		m.screen = "catalog"
	case "up", "k":
		if m.choice > 0 {
			m.choice--
		}
	case "down", "j":
		if m.choice < len(m.choices)-1 {
			m.choice++
		}
	case "enter":
		if len(m.choices) > 0 {
			if m.screen == "folders" {
				m.folderID = m.choices[m.choice].id
				m.selected = 0
				m.screen = "catalog"
			} else {
				cred, _ := m.doc.Credential(m.choices[m.choice].id)
				return m.launch(m.connection, cred)
			}
		}
	}
	return nil
}

func (m *Model) launch(c domain.Connection, cred domain.Credential) tea.Cmd {
	cmd, cleanup, err := m.runner.Prepare(c, cred)
	if err != nil {
		m.screen = "catalog"
		m.setStatus(err.Error(), true)
		return nil
	}
	m.screen = "ssh"
	m.lastAction = time.Now()
	return tea.Exec(&sshclient.TerminalCommand{Cmd: cmd, Runner: m.runner}, func(err error) tea.Msg { cleanup(); return sshDoneMsg{err, time.Now()} })
}

func (m *Model) View() string {
	if m.screen == "ssh" {
		return ""
	}
	if m.width < 32 || m.height < 12 || m.screen != "catalog" && m.height < 16 {
		return m.smallView()
	}
	if m.screen == "catalog" {
		return m.catalogView()
	}
	width := m.width - 8
	var body strings.Builder
	if m.screen == "busy" {
		body.WriteString("Обрабатываем хранилище…\n")
	} else if m.screen == "files" {
		body.WriteString(m.browserView())
	} else if m.screen == "references" {
		body.WriteString(m.referencePickerView())
	} else if m.screen == "key-source" {
		body.WriteString("Источник встроенного ключа\n\n")
		for i, label := range []string{"Выбрать файл", "Вставить содержимое ключа"} {
			if i == m.keySource {
				body.WriteString(selectedLine("› "+label, width) + "\n")
			} else {
				body.WriteString("  " + label + "\n")
			}
		}
		body.WriteString("\n" + muted.Render("←/→ или ↑/↓ выбор · Enter открыть · Esc назад"))
	} else if m.screen == "paste-key" {
		body.WriteString("Вставка приватного ключа\n\n")
		if m.pasteBuffer != "" {
			body.WriteString(fmt.Sprintf("Получен ключ: %d строк. Содержимое скрыто.\n", strings.Count(strings.TrimSpace(m.pasteBuffer), "\n")+1))
		} else {
			body.WriteString("Скопируйте весь ключ, включая строки BEGIN и END.\n")
		}
		body.WriteString("\nВставьте сочетанием вашего терминала (⌘V / Ctrl+Shift+V)\nили Ctrl+V из системного буфера обмена.\n\n" + muted.Render("Enter использовать · Ctrl+U очистить · Esc отменить"))
	} else if m.form != nil {
		start := 0
		count := (m.height - 16) / 3
		if count < 1 {
			count = 1
		}
		visible := m.form.visibleFields()
		focusPos := 0
		for i, index := range visible {
			if index == m.form.focus {
				focusPos = i
			}
		}
		if focusPos >= count {
			start = focusPos - count + 1
		}
		for pos := start; pos < len(visible) && pos < start+count; pos++ {
			i := visible[pos]
			f := m.form.fields[i]
			label := clean(f.label)
			if i == m.form.focus {
				label = accent.Render(label)
			}
			f.input.Width = width - 4
			value := f.input.View()
			if m.form.purpose == "credential" && i == 2 {
				value = "‹ " + authLabel(f.input.Value()) + " ›"
			}
			if m.form.purpose == "credential" && i == 3 {
				value = m.keyFieldView()
			}
			if m.form.isReferenceField(i) {
				value = m.referenceFieldView(i)
			}
			if i == 0 && (m.form.purpose == "merge" || m.form.purpose == "export") {
				value = clean(f.input.Value())
				if value == "" {
					value = "[ Выбрать файл… ]"
				}
				value += " · Enter выбрать"
			}
			body.WriteString(fitLine(label, width) + "\n" + fitLine(value, width) + "\n\n")
		}
		body.WriteString(muted.Render("Tab/↑/↓ поле · Ctrl+S сохранить · Enter далее/готово · Esc отменить"))
		if m.form.purpose == "credential" {
			body.WriteString("\n" + muted.Render("←/→ тип · Enter в поле ключа — выбрать · Ctrl+B файл · Ctrl+V встроенный ключ"))
		}
		if m.form.purpose == "connection" || m.form.purpose == "folder" {
			body.WriteString("\n" + muted.Render("Enter в поле папки/кредов — выбор из списка · Backspace очистить выбор"))
		}
	} else if m.screen == "conflicts" {
		body.WriteString("Конфликт изменений: выберите версию каждого объекта\n\n")
		limit := m.height - 19
		if limit < 1 {
			limit = 1
		}
		start := 0
		if m.conflictPos >= limit {
			start = m.conflictPos - limit + 1
		}
		for i := start; i < len(m.conflictIDs) && i < start+limit; i++ {
			key := m.conflictIDs[i]
			choice := m.decisions[key]
			if choice == "" {
				choice = "не выбрано"
			}
			line := fmt.Sprintf("  %s [%s]", m.describeConflict(m.doc, key), choice)
			if i == m.conflictPos {
				line = selectedLine("› "+strings.TrimSpace(line), width)
			}
			body.WriteString(line + "\n")
		}
		if len(m.conflictIDs) > 0 {
			key := m.conflictIDs[m.conflictPos]
			body.WriteString("\nЛокально: " + m.describeConflict(m.doc, key) + "\nВ файле: " + m.describeConflict(m.conflictRemote, key) + "\n")
		}
		body.WriteString("\n" + muted.Render("Секреты скрыты. Выбирается весь профиль, включая пароль и ключ.") + "\n" + muted.Render("↑/↓ объект · ← локальная · → версия файла · Enter сохранить · Esc назад"))
	} else if m.screen == "confirm" {
		prompt := "Удалить выбранный объект?"
		if m.confirmAction == "quit" {
			prompt = "Есть несохранённые изменения. Выйти и потерять их? E в каталоге сохраняет копию."
		}
		if m.confirmAction == "reload" {
			prompt = "Отбросить несохранённые изменения и переоткрыть хранилище?"
		}
		body.WriteString(prompt + "\n\n" + muted.Render("y/Enter подтвердить · n/Esc отменить"))
	} else if m.screen == "credentials" || m.screen == "folders" {
		title := "Выберите креды"
		if m.screen == "folders" {
			title = "Выберите папку"
		}
		body.WriteString(title + "\n\n")
		limit := m.height - 15
		if limit < 1 {
			limit = 1
		}
		start := 0
		if m.choice >= limit {
			start = m.choice - limit + 1
		}
		for i := start; i < len(m.choices) && i < start+limit; i++ {
			r := m.choices[i]
			line := "  " + clean(r.name) + " · " + clean(r.detail)
			if i == m.choice {
				line = selectedLine("› "+clean(r.name)+" · "+clean(r.detail), width)
			}
			body.WriteString(line + "\n")
		}
		body.WriteString("\n" + muted.Render("↑/↓ выбрать · Enter подтвердить · Esc назад"))
	} else {
		return m.catalogView()
	}
	return m.dialogView(body.String())
}
