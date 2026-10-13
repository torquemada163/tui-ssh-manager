package vault

import (
	"fmt"
	"reflect"
	"sort"

	"github.com/torquemada163/tui-ssh-manager/internal/domain"
)

// Conflict deliberately contains no object contents or secrets.
type Conflict struct{ Objects []string }

func (c *Conflict) Error() string {
	return fmt.Sprintf("conflicting edits to %d object(s); export your changes or reopen the vault", len(c.Objects))
}

func mergeObjects[T any](base, local, remote []T, id func(T) string, kind string, choices map[string]string) ([]T, []string) {
	b, l, r := map[string]T{}, map[string]T{}, map[string]T{}
	keys := map[string]bool{}
	for _, v := range base {
		k := id(v)
		b[k] = v
		keys[k] = true
	}
	for _, v := range local {
		k := id(v)
		l[k] = v
		keys[k] = true
	}
	for _, v := range remote {
		k := id(v)
		r[k] = v
		keys[k] = true
	}
	order := make([]string, 0, len(keys))
	for k := range keys {
		order = append(order, k)
	}
	sort.Strings(order)
	var out []T
	var conflicts []string
	for _, k := range order {
		bv, bok := b[k]
		lv, lok := l[k]
		rv, rok := r[k]
		localChanged := lok != bok || !reflect.DeepEqual(lv, bv)
		remoteChanged := rok != bok || !reflect.DeepEqual(rv, bv)
		if localChanged && remoteChanged && (lok != rok || !reflect.DeepEqual(lv, rv)) {
			switch choices[kind+":"+k] {
			case "local":
				if lok {
					out = append(out, lv)
				}
			case "remote":
				if rok {
					out = append(out, rv)
				}
			default:
				conflicts = append(conflicts, kind+":"+k)
			}
			continue
		}
		if localChanged {
			if lok {
				out = append(out, lv)
			}
		} else if rok {
			out = append(out, rv)
		}
	}
	return out, conflicts
}

func Merge(base, local, remote domain.Document) (domain.Document, error) {
	return MergeSelected(base, local, remote, nil)
}

func MergeSelected(base, local, remote domain.Document, choices map[string]string) (domain.Document, error) {
	if base.ID != local.ID || base.ID != remote.ID {
		return domain.Document{}, fmt.Errorf("vault identity changed; reopen the vault")
	}
	out := remote
	var conflicts []string
	var c []string
	out.Credentials, c = mergeObjects(base.Credentials, local.Credentials, remote.Credentials, func(v domain.Credential) string { return v.ID }, "credential", choices)
	conflicts = append(conflicts, c...)
	out.Connections, c = mergeObjects(base.Connections, local.Connections, remote.Connections, func(v domain.Connection) string { return v.ID }, "connection", choices)
	conflicts = append(conflicts, c...)
	out.Folders, c = mergeObjects(base.Folders, local.Folders, remote.Folders, func(v domain.Folder) string { return v.ID }, "folder", choices)
	conflicts = append(conflicts, c...)
	if len(conflicts) > 0 {
		return domain.Document{}, &Conflict{Objects: conflicts}
	}
	if err := out.Validate(); err != nil {
		return domain.Document{}, fmt.Errorf("merged edits break references: %w", err)
	}
	out.Revision = domain.NewID()
	return out, nil
}

// Copies may lack a common ancestor. Absence must not imply deletion.
func MergeCopy(local, other domain.Document, choices map[string]string) (domain.Document, error) {
	base := domain.Document{Schema: domain.SchemaVersion, ID: local.ID, Revision: local.Revision}
	return MergeSelected(base, local, other, choices)
}
