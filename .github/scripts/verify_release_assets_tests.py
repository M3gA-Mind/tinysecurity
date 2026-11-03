import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from verify_release_assets import PLATFORMS, verify_release_assets


class VerifyReleaseAssetsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.archives = {}
        for platform in sorted(PLATFORMS):
            extension = "zip" if platform.startswith("windows-") else "tar.gz"
            archive = self.root / f"tinysecurity-module-0.18.0-{platform}.{extension}"
            archive.write_bytes(platform.encode())
            self.archives[archive.name] = hashlib.sha256(archive.read_bytes()).hexdigest()
        self.write_manifest()

    def tearDown(self):
        self.directory.cleanup()

    def write_manifest(self):
        entries = "\n".join(f'"{name}" = "{digest}"' for name, digest in self.archives.items())
        (self.root / "checksum.toml").write_text(f"[sha256]\n{entries}\n", encoding="utf-8")

    def test_accepts_all_sixteen_archives_with_matching_digests(self):
        verify_release_assets(self.root)

    def test_rejects_missing_platform_archive(self):
        (self.root / "tinysecurity-module-0.18.0-fedora-43-arm64.tar.gz").unlink()
        with self.assertRaisesRegex(ValueError, "expected 16 archives"):
            verify_release_assets(self.root)

    def test_rejects_checksum_that_does_not_match_archive(self):
        name = next(iter(self.archives))
        self.archives[name] = "0" * 64
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            verify_release_assets(self.root)


if __name__ == "__main__":
    unittest.main()
