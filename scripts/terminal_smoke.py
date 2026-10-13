#!/usr/bin/env python3
"""Exercise the actual TUI and inherited terminal with a controlled ssh stand-in.

Usage: python3 scripts/terminal_smoke.py ./bin/sshm
No real credentials or SSH hosts are used. All artifacts live in a temp folder.
"""
import json
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import sys
import tempfile
import termios
import time


def main():
    binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else "bin/sshm").resolve())
    with tempfile.TemporaryDirectory(prefix="sshm-terminal-") as directory:
        root = Path(directory)
        report = root / "terminal.json"
        hidden = root / ".ssh" / ".keys"
        hidden.mkdir(parents=True)
        key_path = hidden / "id_ed25519"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key_path)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        fixture_key = key_path.read_text()
        fake = root / "ssh"
        fake.write_text("""#!/usr/bin/env python3
import json, os, signal, subprocess, sys, termios
flags = termios.tcgetattr(0)
data = {
  'tty': [os.isatty(fd) for fd in (0, 1, 2)],
  'terminals': [os.ttyname(fd) for fd in (0, 1, 2)],
  'canonical': bool(flags[3] & termios.ICANON),
  'echo': bool(flags[3] & termios.ECHO),
  'args': sys.argv[1:],
}
def ask(prompt):
    return subprocess.check_output([os.environ['SSH_ASKPASS'], prompt], text=True).strip()
data['host_confirmed'] = ask('Are you sure you want to continue connecting (yes/no/[fingerprint])?') == 'yes'
data['password_supplied'] = ask("alice@localhost's password:") == 'controlled-password'
data['otp_supplied'] = ask('Verification code:') == '123456'
with open(os.environ['SSHM_TEST_REPORT'], 'w') as f:
    json.dump(data, f)
signal.signal(signal.SIGINT, lambda *_: print('SSH_INTERRUPT', flush=True))
signal.signal(signal.SIGWINCH, lambda *_: print('SSH_RESIZE', flush=True))
print('SSH_READY', flush=True)
while True:
    line = sys.stdin.readline()
    if not line or line.strip() == 'exit':
        break
print('SSH_FINISHED', flush=True)
""")
        fake.chmod(0o700)
        pid, fd = pty.fork()
        if pid == 0:
            os.environ.update(TERM="xterm-256color", NO_COLOR="1",
                              HOME=str(root),
                              SSHM_TEST_REPORT=str(report),
                              PATH=str(root) + ":" + os.environ["PATH"])
            os.execv(binary, [binary, "-vault", str(root / "test.sshvault"), "-lock-after", "0"])
        output = bytearray()

        def wait_for(text, timeout=12):
            target = text.encode()
            end = time.monotonic() + timeout
            while time.monotonic() < end:
                if target in output:
                    return
                ready, _, _ = select.select([fd], [], [], 0.1)
                if ready:
                    try:
                        chunk = os.read(fd, 65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    output.extend(chunk)
            decoded = output.decode(errors="replace")
            diagnostic = "\n".join(line for line in decoded.splitlines() if 'SSHM authentication' in line)
            raise AssertionError("terminal did not display: " + text + "\n" + diagnostic + "\n" + decoded[-2500:])

        def send(data):
            os.write(fd, data.encode() if isinstance(data, str) else data)
            time.sleep(0.12)

        def clear_output():
            while select.select([fd], [], [], 0)[0]:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                output.extend(chunk)
            output.clear()

        try:
            termios.tcsetwinsize(fd, (35, 120))
            wait_for("Создание зашифрованного хранилища")
            send("test-master-password\ttest-master-password\x13")
            wait_for("Хранилище открыто")
            send(b"\x1b[Cn")  # right arrow to credentials, new credential
            wait_for("Пользователь")
            send("admin\talice\t")
            send(b"\x1b[D\tcontrolled-password\x13")  # agent -> password with left arrow
            wait_for("Изменения сохранены")
            clear_output()
            send(b"\x1b[Dn")  # left arrow back to connections, new connection
            wait_for("Адрес (hostname или IP)")
            send("test-host\tlocalhost\t\t\t\r")
            wait_for("Выберите креды")
            send(b"\x1b[B \r")  # choose admin with checkbox, apply
            send(b"\t\r")
            wait_for("Выберите профиль по умолчанию")
            send(b"\x1b[B\r\x13")
            wait_for("Изменения сохранены")
            clear_output()
            send("\r")
            wait_for('Are you sure you want to continue connecting')
            send('yes\n')
            wait_for('Verification code:')
            send('123456\n')
            wait_for("SSH_READY")
            data = json.loads(report.read_text())
            assert data["tty"] == [True, True, True], data
            assert len(set(data["terminals"])) == 1, data
            assert data["canonical"] and data["echo"], data
            assert data["args"][-2:] == ["--", "localhost"], data
            assert data['host_confirmed'] and data['password_supplied'] and data['otp_supplied'], data
            assert 'controlled-password' not in data['args'], data
            send(b"\x03")
            wait_for("SSH_INTERRUPT")
            termios.tcsetwinsize(fd, (40, 130))
            wait_for("SSH_RESIZE")
            clear_output()
            send("exit\n")
            wait_for("SSH завершён")
            assert not termios.tcgetattr(fd)[3] & termios.ICANON, "TUI did not resume raw mode"
            clear_output()
            send("l")
            wait_for("Разблокировка хранилища")
            send("incorrect-password\r")
            wait_for("incorrect password or damaged vault")
            clear_output()
            send("test-master-password\r")
            wait_for("Хранилище открыто")
            clear_output()
            send(b"\x1b[Cn")
            wait_for("Пользователь")
            send("local-key-test\talice\t")
            send(b"\x1b[C\t\r")  # local key, key field, browser
            wait_for("Скрытые файлы и папки отображаются")
            send(b"\x1b[B\r")  # hidden .keys directory (after ..)
            wait_for(".keys")
            send(b"\x1b[B\r")  # id_ed25519 (after ..)
            wait_for("Файл ключа выбран")
            assert b"~/.ssh/.keys/id_ed25519" in output, "browser did not select a portable path for the hidden-directory key"
            send(b"\x13")
            wait_for("Изменения сохранены")
            clear_output()
            send("n")
            wait_for("Пользователь")
            send("embedded-key-test\talice\t")
            send(b"\x1b[C\x1b[C\t\r")  # stored key, source selector
            wait_for("Источник встроенного ключа")
            send(b"\x1b[C\r")
            wait_for("Вставка приватного ключа")
            send(b"\x1b[200~" + fixture_key.encode() + b"\x1b[201~")
            wait_for("Ключ получен")
            send(b"\r\x13")
            wait_for("Изменения сохранены")
            assert fixture_key.splitlines()[1].encode() not in output, "pasted key appeared on screen"
            send("q")
            end = time.monotonic() + 5
            while time.monotonic() < end:
                if select.select([fd], [], [], 0.05)[0]:
                    chunk = os.read(fd, 65536)
                    if chunk:
                        output.extend(chunk)
                exited, status = os.waitpid(pid, os.WNOHANG)
                if exited:
                    assert os.waitstatus_to_exitcode(status) == 0
                    pid = None
                    break
                time.sleep(0.05)
            assert pid is None, "manager did not exit"
            assert termios.tcgetattr(fd)[3] & termios.ICANON, "terminal not restored on exit"
            print("PASS: vault CRUD, arrow selectors, hidden-file browser, embedded key paste, original terminal, host confirmation, saved password, OTP, Ctrl+C, resize, return to TUI, unlock retry, exit cleanup")
        finally:
            os.close(fd)  # Hang up the test terminal, including helper processes.
            if pid is not None:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(pid, 0)
                except ChildProcessError:
                    pass


if __name__ == "__main__":
    main()
