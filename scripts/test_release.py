import argparse
import hashlib
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import release


class ReleaseTests(unittest.TestCase):
    def test_notes_are_exactly_the_requested_release(self):
        source = "## [Unreleased]\n- Future\n\n## [0.2.0] - 2026-10-21\n\n### Added\n- Tree\n\n## [0.1.0]\n- First\n"
        self.assertEqual(release.notes(source, "0.2.0"), "### Added\n- Tree\n")
        with self.assertRaises(ValueError):
            release.notes(source, "0.3.0")
        with self.assertRaises(ValueError):
            release.notes("## [0.2.0]\n\n### Added\n", "0.2.0")

    def test_version_rejects_invalid_or_unsafe_names(self):
        for value in ("v0.1.0", "0.1.0", "v1.2.3-rc.1"):
            self.assertEqual(release.version(value), value.removeprefix("v"))
        for value in ("dev", "v1.2", "v01.2.3", "v1.2.3-rc.01", "../1.2.3", "1.2.3;id", "1.2.3\n"):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                release.version(value)

    def test_archives_only_include_distribution_files_and_valid_checksums(self):
        environments = []

        def build(args, *, cwd, env, check):
            environments.append((env["GOOS"], env["GOARCH"], env["CGO_ENABLED"]))
            Path(args[args.index("-o") + 1]).write_bytes(b"test binary")
            self.assertIn("main.version=0.1.0", args[args.index("-ldflags") + 1])

        with tempfile.TemporaryDirectory() as directory, patch.object(subprocess, "run", side_effect=build):
            output = Path(directory)
            release.package("0.1.0", output)
            self.assertEqual(set(environments), {(system, arch, "0") for system, arch in release.PLATFORMS})
            lines = (output / "checksums.txt").read_text().splitlines()
            self.assertEqual(len(lines), 4)
            for line in lines:
                digest, name = line.split("  ")
                path = output / name
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
                with tarfile.open(path) as archive:
                    self.assertEqual(archive.getnames(), ["sshm", "README.md", "LICENSE", "CHANGELOG.md"])
                    self.assertEqual(archive.getmember("sshm").mode, 0o755)
                    self.assertEqual(archive.extractfile("sshm").read(), b"test binary")


if __name__ == "__main__":
    unittest.main()
