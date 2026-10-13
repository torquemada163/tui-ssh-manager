package domain

import "testing"

func TestFolderInheritanceAndOverride(t *testing.T) {
	d := NewDocument()
	d.Credentials = []Credential{{ID: "a", Name: "a", Username: "alice", Kind: "agent"}, {ID: "b", Name: "b", Username: "bob", Kind: "agent"}}
	d.Folders = []Folder{{ID: "parent", Name: "parent", CredentialIDs: []string{"a"}}, {ID: "child", Name: "child", ParentID: "parent"}}
	c := Connection{ID: "server", Name: "server", Host: "localhost", Port: 22, FolderID: "child"}
	d.Connections = []Connection{c}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	if ids := d.EffectiveCredentials(c); len(ids) != 1 || ids[0] != "a" {
		t.Fatal("parent credential not inherited")
	}
	c.CredentialIDs = []string{"b"}
	if ids := d.EffectiveCredentials(c); len(ids) != 1 || ids[0] != "b" {
		t.Fatal("explicit credential not preferred")
	}
	d.Folders[0].ParentID = "child"
	if err := d.Validate(); err == nil {
		t.Fatal("folder cycle accepted")
	}
}

func TestRejectDangerousDestinationAndDisplayControls(t *testing.T) {
	for _, host := range []string{"-oProxyCommand=evil", "user@host", "host\n", "host;cmd", "host/anything", "host$(cmd)", "\x1b]52;payload"} {
		if ValidHost(host) {
			t.Fatalf("accepted unsafe host %q", host)
		}
	}
	for _, host := range []string{"localhost", "server.example.org", "192.168.1.1", "2001:db8::1"} {
		if !ValidHost(host) {
			t.Fatalf("rejected valid host %q", host)
		}
	}
	d := NewDocument()
	d.Credentials = []Credential{{ID: "cred", Name: "name\x1b[31m", Username: "alice", Kind: "agent"}}
	if err := d.Validate(); err == nil {
		t.Fatal("terminal escape in name accepted")
	}
}
