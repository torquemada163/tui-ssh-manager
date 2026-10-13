package sshclient

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/torquemada163/tui-ssh-manager/internal/domain"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestMain(m *testing.M) {
	if IsAskpass() {
		if len(os.Args) != 2 || Askpass(os.Args[1]) != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func shortTemp(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "sshm-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}
func conn() domain.Connection {
	return domain.Connection{ID: "conn", Name: "server", Host: "localhost", Port: 22}
}

func TestCommandUsesOriginalTerminalAndNoSecretArguments(t *testing.T) {
	cred := domain.Credential{ID: "cred", Name: "administrator", Username: "alice", Kind: "password", Password: "unique-plaintext-secret"}
	r := &Runner{}
	cmd, cleanup, err := r.Prepare(conn(), cred)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if cmd.Stdin != os.Stdin || cmd.Stdout != os.Stdout || cmd.Stderr != os.Stderr {
		t.Fatal("original terminal replaced")
	}
	if strings.Contains(strings.Join(cmd.Args, " "), cred.Password) || strings.Contains(strings.Join(cmd.Env, "\n"), cred.Password) {
		t.Fatal("secret leaked to process arguments or environment")
	}
	if !strings.Contains(strings.Join(cmd.Args, " "), "StrictHostKeyChecking=ask") {
		t.Fatal("host verification disabled")
	}
}

func TestImportedKeyOnlyExistsInAgentMemory(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	cred := domain.Credential{ID: "cred", Name: "imported", Username: "alice", Kind: "stored-key", PrivateKey: string(pem.EncodeToMemory(block))}
	r := &Runner{}
	cmd, cleanup, err := r.Prepare(conn(), cred)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	var sock string
	for _, arg := range cmd.Args {
		if strings.HasPrefix(arg, "IdentityAgent=") {
			sock = strings.TrimPrefix(arg, "IdentityAgent=")
		}
	}
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	keys, err := agent.NewClient(c).List()
	if err != nil || len(keys) != 1 {
		t.Fatalf("agent identities: %v %v", keys, err)
	}
	files, err := os.ReadDir(filepath.Dir(sock))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".sock") {
			t.Fatal("private key written to disk")
		}
	}
	cleanup()
	if _, err = os.Stat(sock); !os.IsNotExist(err) {
		t.Fatal("agent socket not cleaned")
	}
}

func TestAskpassAuthorizationAndInteractiveFallback(t *testing.T) {
	sock := filepath.Join(shortTemp(t), "auth.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go servePasswords(l, "valid-token", domain.Credential{Password: "stored-secret"})
	request := func(token, prompt string) authResponse {
		t.Helper()
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(time.Second))
		_ = json.NewEncoder(c).Encode(authRequest{Token: token, Prompt: prompt})
		var resp authResponse
		if err = json.NewDecoder(c).Decode(&resp); err != nil {
			t.Fatal(err)
		}
		return resp
	}
	if resp := request("wrong-token", "alice@server's password:"); resp.Found {
		t.Fatal("secret disclosed without authorization")
	}
	if resp := request("valid-token", "Verification code:"); resp.Found {
		t.Fatal("password used as OTP")
	}
	if resp := request("valid-token", "Are you sure you want to continue connecting (yes/no)?"); resp.Found {
		t.Fatal("password used as host confirmation")
	}
	if resp := request("valid-token", "alice@server's password:"); !resp.Found || resp.Value != "stored-secret" {
		t.Fatal("saved password not supplied")
	}
	if resp := request("valid-token", "alice@server's password:"); resp.Found {
		t.Fatal("wrong password repeated automatically")
	}
}

func TestNoShellInterpolation(t *testing.T) {
	cred := domain.Credential{ID: "cred", Name: "key", Username: "alice", Kind: "agent"}
	c := conn()
	c.Host = "-oProxyCommand=touch /tmp/pwned"
	if _, err := Arguments(c, cred); err == nil {
		t.Fatal("option injection accepted")
	}
	c = conn()
	args, err := Arguments(c, cred)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal([]byte(args[len(args)-2]), []byte("--")) {
		t.Fatal("destination not separated from options")
	}
}

func TestRealOpenSSHAuthentication(t *testing.T) {
	for _, kind := range []string{"password", "stored-key", "local-key"} {
		t.Run(kind, func(t *testing.T) {
			_, hostKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			hostSigner, err := ssh.NewSignerFromKey(hostKey)
			if err != nil {
				t.Fatal(err)
			}
			_, userKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			userSigner, _ := ssh.NewSignerFromKey(userKey)
			cred := domain.Credential{ID: "cred", Name: "test", Username: "alice", Kind: kind}
			config := &ssh.ServerConfig{}
			if kind == "password" {
				cred.Password = "test-saved-password"
				config.PasswordCallback = func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
					if meta.User() == "alice" && string(password) == cred.Password {
						return nil, nil
					}
					return nil, fmt.Errorf("denied")
				}
			} else {
				cred.Passphrase = "encrypted-key-passphrase"
				block, _ := ssh.MarshalPrivateKeyWithPassphrase(userKey, "", []byte(cred.Passphrase))
				if kind == "local-key" {
					cred.KeyPath = filepath.Join(shortTemp(t), "id_ed25519")
					if err = os.WriteFile(cred.KeyPath, pem.EncodeToMemory(block), 0600); err != nil {
						t.Fatal(err)
					}
				} else {
					cred.PrivateKey = string(pem.EncodeToMemory(block))
				}
				config.PublicKeyCallback = func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
					if meta.User() == "alice" && bytes.Equal(key.Marshal(), userSigner.PublicKey().Marshal()) {
						return nil, nil
					}
					return nil, fmt.Errorf("denied")
				}
			}
			config.AddHostKey(hostSigner)
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			serverDone := make(chan error, 1)
			go func() {
				raw, err := l.Accept()
				if err != nil {
					serverDone <- err
					return
				}
				defer raw.Close()
				_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
				server, channels, requests, err := ssh.NewServerConn(raw, config)
				if err != nil {
					serverDone <- err
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(requests)
				for newChannel := range channels {
					if newChannel.ChannelType() != "session" {
						_ = newChannel.Reject(ssh.UnknownChannelType, "unsupported")
						continue
					}
					channel, requests, err := newChannel.Accept()
					if err != nil {
						serverDone <- err
						return
					}
					for req := range requests {
						if req.Type == "shell" {
							_ = req.Reply(true, nil)
							_, _ = io.WriteString(channel, "CONTROLLED_SERVER_OK\n")
							_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
							_ = channel.Close()
							serverDone <- nil
							return
						}
						_ = req.Reply(false, nil)
					}
				}
				serverDone <- fmt.Errorf("no shell request")
			}()
			_, portString, _ := net.SplitHostPort(l.Addr().String())
			port, _ := strconv.Atoi(portString)
			known := filepath.Join(shortTemp(t), "known_hosts")
			line := fmt.Sprintf("[127.0.0.1]:%d %s", port, ssh.MarshalAuthorizedKey(hostSigner.PublicKey()))
			if err = os.WriteFile(known, []byte(line), 0600); err != nil {
				t.Fatal(err)
			}
			c := conn()
			c.Host = "127.0.0.1"
			c.Port = port
			r := &Runner{}
			cmd, cleanup, err := r.Prepare(c, cred)
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()
			for i, arg := range cmd.Args {
				if arg == "StrictHostKeyChecking=ask" {
					cmd.Args[i] = "StrictHostKeyChecking=yes"
				}
			}
			cmd.Args = append(cmd.Args[:len(cmd.Args)-2], "-o", "UserKnownHostsFile="+known, "--", c.Host)
			cmd.Stdin = strings.NewReader("")
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err = (&TerminalCommand{Cmd: cmd, Runner: r}).Run(); err != nil {
				t.Fatalf("OpenSSH failed: %v; %s", err, stderr.String())
			}
			if !strings.Contains(stdout.String(), "CONTROLLED_SERVER_OK") {
				t.Fatal("remote shell not reached")
			}
			select {
			case err := <-serverDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("SSH server did not finish")
			}
		})
	}
}
