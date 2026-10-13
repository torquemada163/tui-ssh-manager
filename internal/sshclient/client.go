package sshclient

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/torquemada163/tui-ssh-manager/internal/domain"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

const socketEnv = "SSHM_AUTH_SOCKET"
const tokenEnv = "SSHM_AUTH_TOKEN"

type authRequest struct {
	Token  string
	Prompt string
}
type authResponse struct {
	Value string
	Found bool
}

type Runner struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	cleanup func()
}

// TerminalCommand synchronizes process start with signal-triggered cleanup.
type TerminalCommand struct {
	Cmd    *exec.Cmd
	Runner *Runner
}

func (c *TerminalCommand) SetStdin(r io.Reader) {
	if c.Cmd.Stdin == nil {
		c.Cmd.Stdin = r
	}
}
func (c *TerminalCommand) SetStdout(w io.Writer) {
	if c.Cmd.Stdout == nil {
		c.Cmd.Stdout = w
	}
}
func (c *TerminalCommand) SetStderr(w io.Writer) {
	if c.Cmd.Stderr == nil {
		c.Cmd.Stderr = w
	}
}
func (c *TerminalCommand) Run() error {
	c.Runner.mu.Lock()
	if c.Runner.cmd != c.Cmd {
		c.Runner.mu.Unlock()
		return errors.New("SSH launch cancelled")
	}
	err := c.Cmd.Start()
	c.Runner.mu.Unlock()
	if err != nil {
		return err
	}
	return c.Cmd.Wait()
}

func ExpandPath(path string) (string, error) {
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		path = filepath.Join(home, strings.TrimPrefix(path, "~/"))
	}
	return filepath.Abs(path)
}

func Arguments(c domain.Connection, cred domain.Credential) ([]string, error) {
	d := domain.NewDocument()
	d.Credentials = []domain.Credential{cred}
	c.CredentialIDs = []string{cred.ID}
	c.DefaultCredentialID = cred.ID
	c.FolderID = ""
	d.Connections = []domain.Connection{c}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	args := []string{"-F", "/dev/null", "-p", fmt.Sprint(c.Port), "-l", cred.Username, "-o", "StrictHostKeyChecking=ask", "-o", "ForwardAgent=no", "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3"}
	if cred.Kind == "local-key" {
		path, err := ExpandPath(cred.KeyPath)
		if err != nil {
			return nil, err
		}
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("local key: %w", err)
		}
		if !info.Mode().IsRegular() {
			return nil, errors.New("local key must be a regular file")
		}
		args = append(args, "-i", path, "-o", "IdentitiesOnly=yes")
	}
	if cred.Kind == "password" {
		args = append(args, "-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=keyboard-interactive,password")
	}
	args = append(args, "--", c.Host)
	return args, nil
}

// ValidatePrivateKey checks an import without writing decrypted key material.
func ValidatePrivateKey(pem, passphrase string) error {
	var err error
	if passphrase != "" {
		_, err = ssh.ParseRawPrivateKeyWithPassphrase([]byte(pem), []byte(passphrase))
	} else {
		_, err = ssh.ParseRawPrivateKey([]byte(pem))
	}
	if err != nil {
		return errors.New("cannot decode private key; check format and passphrase")
	}
	return nil
}

func filteredEnv() []string {
	var out []string
	for _, v := range os.Environ() {
		k, _, _ := strings.Cut(v, "=")
		if k != socketEnv && k != tokenEnv && k != "SSH_ASKPASS" && k != "SSH_ASKPASS_REQUIRE" {
			out = append(out, v)
		}
	}
	return out
}

func (r *Runner) Prepare(c domain.Connection, cred domain.Credential) (*exec.Cmd, func(), error) {
	args, err := Arguments(c, cred)
	if err != nil {
		return nil, nil, err
	}
	path, err := exec.LookPath("ssh")
	if err != nil {
		return nil, nil, errors.New("OpenSSH ssh is not installed")
	}
	cmd := exec.Command(path, args...)
	// Preserve actual terminal file descriptors; never substitute pipes or a PTY.
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = filteredEnv()
	var dir string
	var listeners []net.Listener
	var connectionMu sync.Mutex
	connectionsClosed := false
	connections := map[net.Conn]bool{}
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			for _, l := range listeners {
				_ = l.Close()
			}
			connectionMu.Lock()
			connectionsClosed = true
			for c := range connections {
				_ = c.Close()
			}
			connectionMu.Unlock()
			if dir != "" {
				_ = os.RemoveAll(dir)
			}
			r.mu.Lock()
			if r.cmd == cmd {
				r.cmd = nil
				r.cleanup = nil
			}
			r.mu.Unlock()
		})
	}
	fail := func(err error) (*exec.Cmd, func(), error) { cleanup(); return nil, nil, err }
	needsAuth := cred.Kind == "stored-key" || cred.Password != "" || cred.Passphrase != ""
	if needsAuth {
		dir, err = os.MkdirTemp("", "sshm-auth-")
		if err != nil {
			return fail(err)
		}
		if cred.Kind == "stored-key" {
			var key any
			if cred.Passphrase != "" {
				key, err = ssh.ParseRawPrivateKeyWithPassphrase([]byte(cred.PrivateKey), []byte(cred.Passphrase))
			} else {
				key, err = ssh.ParseRawPrivateKey([]byte(cred.PrivateKey))
			}
			if err != nil {
				return fail(errors.New("cannot decode stored private key"))
			}
			keyring := agent.NewKeyring()
			if err = keyring.Add(agent.AddedKey{PrivateKey: key}); err != nil {
				return fail(errors.New("cannot load stored private key"))
			}
			sock := filepath.Join(dir, "agent.sock")
			l, err := net.Listen("unix", sock)
			if err != nil {
				return fail(err)
			}
			listeners = append(listeners, l)
			cmd.Args = append(cmd.Args[:len(cmd.Args)-2], "-o", "IdentityAgent="+sock, "-o", "IdentityFile=none", "-o", "IdentitiesOnly=no", "--", c.Host)
			go func() {
				defer keyring.RemoveAll()
				for {
					conn, err := l.Accept()
					if err != nil {
						return
					}
					connectionMu.Lock()
					if connectionsClosed {
						connectionMu.Unlock()
						_ = conn.Close()
						return
					}
					connections[conn] = true
					connectionMu.Unlock()
					go func() {
						defer func() { _ = conn.Close(); connectionMu.Lock(); delete(connections, conn); connectionMu.Unlock() }()
						_ = conn.SetDeadline(time.Now().Add(24 * time.Hour))
						_ = agent.ServeAgent(keyring, conn)
					}()
				}
			}()
		}
		if cred.Password != "" || (cred.Kind == "local-key" && cred.Passphrase != "") {
			exe, err := os.Executable()
			if err != nil {
				return fail(err)
			}
			sock := filepath.Join(dir, "auth.sock")
			l, err := net.Listen("unix", sock)
			if err != nil {
				return fail(err)
			}
			listeners = append(listeners, l)
			token := domain.NewID() + domain.NewID()
			cmd.Env = append(cmd.Env, "SSH_ASKPASS="+exe, "SSH_ASKPASS_REQUIRE=force", socketEnv+"="+sock, tokenEnv+"="+token)
			go servePasswords(l, token, cred)
		}
	}
	r.mu.Lock()
	r.cmd = cmd
	r.cleanup = cleanup
	r.mu.Unlock()
	return cmd, cleanup, nil
}

func servePasswords(l net.Listener, token string, cred domain.Credential) {
	usedPassword, usedPhrase := false, false
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		var req authRequest
		resp := authResponse{}
		if json.NewDecoder(io.LimitReader(conn, 8192)).Decode(&req) == nil && subtle.ConstantTimeCompare([]byte(req.Token), []byte(token)) == 1 {
			prompt := strings.ToLower(strings.TrimSpace(req.Prompt))
			if !usedPassword && cred.Password != "" && strings.HasSuffix(prompt, "password:") {
				resp = authResponse{Value: cred.Password, Found: true}
				usedPassword = true
			}
			if !usedPhrase && cred.Kind == "local-key" && cred.Passphrase != "" && strings.HasPrefix(prompt, "enter passphrase for key ") {
				expected, err := ExpandPath(cred.KeyPath)
				if err == nil && strings.Contains(req.Prompt, "'"+expected+"'") {
					resp = authResponse{Value: cred.Passphrase, Found: true}
					usedPhrase = true
				}
			}
		}
		_ = json.NewEncoder(conn).Encode(resp)
		_ = conn.Close()
	}
}

func (r *Runner) Close() {
	r.mu.Lock()
	cmd, cleanup := r.cmd, r.cleanup
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	r.mu.Unlock()
	if cleanup != nil {
		cleanup()
	}
}

// IsAskpass uses a private socket marker, since OpenSSH invokes the executable
// with the prompt alone, without a subcommand.
func IsAskpass() bool { return os.Getenv(socketEnv) != "" && os.Getenv(tokenEnv) != "" }

func Askpass(prompt string) error {
	conn, err := net.DialTimeout("unix", os.Getenv(socketEnv), 3*time.Second)
	if err != nil {
		return errors.New("authentication helper unavailable")
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	err = json.NewEncoder(conn).Encode(authRequest{Token: os.Getenv(tokenEnv), Prompt: prompt})
	var resp authResponse
	if err == nil {
		err = json.NewDecoder(io.LimitReader(conn, 1<<20)).Decode(&resp)
	}
	_ = conn.Close()
	if err != nil {
		return err
	}
	if resp.Found {
		_, err = fmt.Fprintln(os.Stdout, resp.Value)
		return err
	}
	// Host-key confirmations, OTP and repeated password attempts stay interactive.
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("no terminal for interactive authentication: %w", err)
	}
	defer tty.Close()
	if !domain.SafeText(strings.ReplaceAll(prompt, "\n", "")) {
		return errors.New("invalid authentication prompt")
	}
	_, _ = fmt.Fprint(tty, prompt+" ")
	var answer []byte
	if strings.Contains(strings.ToLower(prompt), "yes/no") {
		var b [1]byte
		for len(answer) < 4096 {
			n, e := tty.Read(b[:])
			if e != nil {
				return e
			}
			if n == 1 {
				if b[0] == '\n' {
					break
				}
				answer = append(answer, b[0])
			}
		}
	} else {
		answer, err = term.ReadPassword(int(tty.Fd()))
		_, _ = fmt.Fprintln(tty)
		if err != nil {
			return err
		}
	}
	defer func() {
		for i := range answer {
			answer[i] = 0
		}
	}()
	_, err = fmt.Fprintln(os.Stdout, string(answer))
	return err
}
