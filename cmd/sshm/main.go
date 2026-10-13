package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/torquemada163/tui-ssh-manager/internal/sshclient"
	"github.com/torquemada163/tui-ssh-manager/internal/ui"
	"golang.org/x/term"
)

var version = "dev"

func main() { os.Exit(run()) }

func run() int {
	if sshclient.IsAskpass() {
		if len(os.Args) != 2 {
			return 1
		}
		if err := sshclient.Askpass(os.Args[1]); err != nil {
			fmt.Fprintln(os.Stderr, "SSHM authentication helper:", err)
			return 1
		}
		return 0
	}
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	flags := flag.NewFlagSet("sshm", flag.ContinueOnError)
	path := flags.String("vault", filepath.Join(home, ".config", "sshm", "connections.sshvault"), "путь к зашифрованному хранилищу (может быть в облачной папке)")
	idle := flags.Duration("lock-after", 5*time.Minute, "таймаут блокировки, 0 — отключить")
	showVersion := flags.Bool("version", false, "показать версию")
	if err := flags.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *showVersion {
		fmt.Println("sshm " + version)
		return 0
	}
	if flags.NArg() != 0 || *idle < 0 {
		fmt.Fprintln(os.Stderr, "некорректные аргументы; используйте sshm -help")
		return 2
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Fprintln(os.Stderr, "sshm нужно запускать в интерактивном терминале")
		return 1
	}
	abs, err := sshclient.ExpandPath(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	runner := &sshclient.Runner{}
	defer runner.Close()
	model := ui.New(abs, runner, *idle)
	defer model.Close()
	program := tea.NewProgram(model, tea.WithAltScreen(), tea.WithoutSignalHandler())
	// Ctrl+C is a key in the TUI, and belongs to ssh in canonical mode. The
	// parent must not quit because the terminal also sends it SIGINT during ssh.
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case sig := <-signals:
				if sig != syscall.SIGINT {
					runner.Close()
					program.Kill()
					return
				}
			case <-done:
				return
			}
		}
	}()
	if _, err := program.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
