package domain

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

const SchemaVersion = 1

type Folder struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	ParentID      string   `json:"parent_id,omitempty"`
	CredentialIDs []string `json:"credential_ids,omitempty"`
}

type Credential struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Username   string `json:"username"`
	Kind       string `json:"kind"` // agent, local-key, stored-key, password
	Password   string `json:"password,omitempty"`
	KeyPath    string `json:"key_path,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

type Connection struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	Host                string   `json:"host"`
	Port                int      `json:"port"`
	FolderID            string   `json:"folder_id,omitempty"`
	Tags                string   `json:"tags,omitempty"`
	Notes               string   `json:"notes,omitempty"`
	CredentialIDs       []string `json:"credential_ids,omitempty"`
	DefaultCredentialID string   `json:"default_credential_id,omitempty"`
}

type Document struct {
	Schema      int          `json:"schema"`
	ID          string       `json:"id"`
	Revision    string       `json:"revision"`
	Folders     []Folder     `json:"folders"`
	Credentials []Credential `json:"credentials"`
	Connections []Connection `json:"connections"`
}

func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

func NewDocument() Document {
	return Document{Schema: SchemaVersion, ID: NewID(), Revision: NewID(), Folders: []Folder{}, Credentials: []Credential{}, Connections: []Connection{}}
}

func (d Document) Credential(id string) (Credential, bool) {
	for _, c := range d.Credentials {
		if c.ID == id {
			return c, true
		}
	}
	return Credential{}, false
}

func (d Document) EffectiveCredentials(c Connection) []string {
	if len(c.CredentialIDs) > 0 {
		return c.CredentialIDs
	}
	seen := map[string]bool{}
	for id := c.FolderID; id != "" && !seen[id]; {
		seen[id] = true
		found := false
		for _, f := range d.Folders {
			if f.ID == id {
				if len(f.CredentialIDs) > 0 {
					return f.CredentialIDs
				}
				id, found = f.ParentID, true
				break
			}
		}
		if !found {
			break
		}
	}
	return nil
}

func SafeText(s string) bool {
	for _, r := range s {
		if r < 32 || r == 127 || (r >= 128 && r <= 159) {
			return false
		}
	}
	return true
}

func ValidHost(host string) bool {
	if host == "" || strings.HasPrefix(host, "-") || strings.ContainsAny(host, " \t\r\n/@\\") || !SafeText(host) {
		return false
	}
	if strings.Contains(host, ":") {
		return net.ParseIP(host) != nil
	}
	for _, r := range host {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func (d Document) Validate() error {
	if d.Schema != SchemaVersion || d.ID == "" || d.Revision == "" {
		return fmt.Errorf("unsupported or invalid document")
	}
	ids := map[string]bool{}
	check := func(id, name string) error {
		if id == "" || ids[id] || !SafeText(id) || strings.Contains(id, ":") {
			return fmt.Errorf("missing or duplicate object ID")
		}
		ids[id] = true
		if strings.TrimSpace(name) == "" || !SafeText(name) {
			return fmt.Errorf("invalid object name")
		}
		return nil
	}
	folders := map[string]Folder{}
	creds := map[string]bool{}
	names := map[string]bool{}
	for _, c := range d.Credentials {
		if err := check(c.ID, c.Name); err != nil {
			return err
		}
		name := strings.ToLower(c.Name)
		if strings.ContainsAny(c.Password+c.Passphrase, "\r\n") {
			return fmt.Errorf("invalid credential name or multiline secret")
		}
		if names[name] {
			return fmt.Errorf("credential names must be unique")
		}
		names[name] = true
		if c.Username == "" || strings.HasPrefix(c.Username, "-") || strings.ContainsAny(c.Username, " \t\r\n/@") || !SafeText(c.Username) {
			return fmt.Errorf("invalid username in %s", c.Name)
		}
		switch c.Kind {
		case "password":
			if c.Password == "" {
				return fmt.Errorf("password required for %s", c.Name)
			}
		case "local-key":
			if c.KeyPath == "" || !SafeText(c.KeyPath) {
				return fmt.Errorf("key path required for %s", c.Name)
			}
		case "stored-key":
			if c.PrivateKey == "" {
				return fmt.Errorf("private key required for %s", c.Name)
			}
		case "agent":
		default:
			return fmt.Errorf("invalid authentication type for %s", c.Name)
		}
		creds[c.ID] = true
	}
	folderNames := map[string]bool{}
	for _, f := range d.Folders {
		if err := check(f.ID, f.Name); err != nil {
			return err
		}
		name := strings.ToLower(f.Name)
		if folderNames[name] {
			return fmt.Errorf("folder names must be unique")
		}
		folderNames[name] = true
		folders[f.ID] = f
	}
	refs := func(list []string) error {
		seen := map[string]bool{}
		for _, id := range list {
			if !creds[id] || seen[id] {
				return fmt.Errorf("missing or duplicate credential reference")
			}
			seen[id] = true
		}
		return nil
	}
	for _, f := range d.Folders {
		if err := refs(f.CredentialIDs); err != nil {
			return err
		}
		seen := map[string]bool{f.ID: true}
		for id := f.ParentID; id != ""; {
			parent, ok := folders[id]
			if !ok {
				return fmt.Errorf("missing parent folder")
			}
			if seen[id] {
				return fmt.Errorf("folder cycle")
			}
			seen[id] = true
			id = parent.ParentID
		}
	}
	for _, c := range d.Connections {
		if err := check(c.ID, c.Name); err != nil {
			return err
		}
		if !ValidHost(c.Host) || c.Port < 1 || c.Port > 65535 {
			return fmt.Errorf("invalid host or port in %s", c.Name)
		}
		if !SafeText(c.Tags) || !SafeText(c.Notes) {
			return fmt.Errorf("control characters in connection metadata")
		}
		if c.FolderID != "" {
			if _, ok := folders[c.FolderID]; !ok {
				return fmt.Errorf("missing connection folder")
			}
		}
		if err := refs(c.CredentialIDs); err != nil {
			return err
		}
		if c.DefaultCredentialID != "" {
			found := false
			for _, id := range d.EffectiveCredentials(c) {
				if id == c.DefaultCredentialID {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("default credential is not assigned to %s", c.Name)
			}
		}
	}
	return nil
}
