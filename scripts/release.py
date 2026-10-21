#!/usr/bin/env python3
"""Build release archives and extract user-facing notes using only the stdlib."""

import argparse
import gzip
import hashlib
import io
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SEMVER = re.compile(
    r"v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
)
PLATFORMS = [(system, arch) for system in ("darwin", "linux") for arch in ("arm64", "amd64")]


def version(value):
    match = SEMVER.fullmatch(value)
    if not match:
        raise argparse.ArgumentTypeError("expected a version such as v0.1.0 or v0.2.0-rc.1")
    if match[4] and any(part.isdigit() and len(part) > 1 and part[0] == "0" for part in match[4].split(".")):
        raise argparse.ArgumentTypeError("numeric prerelease identifiers must not have leading zeroes")
    return value.removeprefix("v")


def notes(changelog, release_version):
    heading = re.compile(r"^## \[" + re.escape(release_version) + r"\](?: - \d{4}-\d{2}-\d{2})?$")
    lines = changelog.splitlines()
    for index, line in enumerate(lines):
        if heading.fullmatch(line):
            end = next((i for i in range(index + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
            body = "\n".join(lines[index + 1:end]).strip()
            if not any(line.startswith("- ") for line in body.splitlines()):
                raise ValueError("release notes must contain at least one changelog entry")
            return body + "\n"
    raise ValueError(f"missing ## [{release_version}] section in CHANGELOG.md")


def archive(path, files):
    # Stable headers and ordering also keep checksums independent of local mtimes.
    with path.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode="w") as tar:
            for name, data, mode in files:
                info = tarfile.TarInfo(name)
                info.size, info.mode = len(data), mode
                tar.addfile(info, io.BytesIO(data))


def package(release_version, output):
    output.mkdir(parents=True, exist_ok=True)
    paths = []
    with tempfile.TemporaryDirectory(prefix="sshm-release-") as directory:
        binary = Path(directory) / "sshm"
        for system, arch in PLATFORMS:
            env = dict(os.environ, CGO_ENABLED="0", GOOS=system, GOARCH=arch)
            subprocess.run([
                "go", "build", "-trimpath", "-buildvcs=false",
                "-ldflags", f"-s -w -X main.version={release_version}",
                "-o", str(binary), "./cmd/sshm",
            ], cwd=ROOT, env=env, check=True)
            path = output / f"sshm_{release_version}_{system}_{arch}.tar.gz"
            files = [("sshm", binary.read_bytes(), 0o755)]
            files.extend((name, (ROOT / name).read_bytes(), 0o644) for name in ("README.md", "LICENSE", "CHANGELOG.md"))
            archive(path, files)
            paths.append(path)
            print(path)
    manifest = output / "checksums.txt"
    manifest.write_text("".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in sorted(paths)), encoding="utf-8")
    print(manifest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("package", "notes"))
    parser.add_argument("--version", required=True, type=version)
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    if args.command == "notes":
        try:
            print(notes((ROOT / "CHANGELOG.md").read_text(encoding="utf-8"), args.version), end="")
        except ValueError as error:
            parser.error(str(error))
    else:
        package(args.version, args.output.resolve())


if __name__ == "__main__":
    main()
