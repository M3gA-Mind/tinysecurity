import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from verify_release_assets import PLATFORMS, archive_sha256, verify_release_assets


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

    def test_archive_digest_comes_from_the_sha256_table_only(self):
        # The published v0.18.4 manifest: the archive name keys both tables.
        archive = "tinysecurity-module-0.18.4-ubuntu-24.04-x86_64.tar.gz"
        archive_digest = "2e51299127281ae7c524c606590bb41ae2f635536c63791abe327d7f6abed0ba"
        library_digest = "f4b79247cad5b7c12c1423ada6cb76bb0ac8a52c54b315b35c5d1bc2aeca3245"
        (self.root / "checksum.toml").write_text(
            f'[sha256]\n"{archive}" = "{archive_digest}"\n'
            f'\n[library_sha256]\n"{archive}" = "{library_digest}"\n',
            encoding="utf-8",
        )
        self.assertEqual(archive_sha256(self.root / "checksum.toml", archive), archive_digest)

    def test_archive_digest_refuses_a_missing_or_malformed_entry(self):
        manifest = self.root / "checksum.toml"
        manifest.write_text('[sha256]\n"present.tar.gz" = "not-a-digest"\n', encoding="utf-8")
        for archive in ("present.tar.gz", "absent.tar.gz"):
            with self.assertRaisesRegex(ValueError, "no valid SHA-256"):
                archive_sha256(manifest, archive)
        manifest.write_text('[library_sha256]\n"present.tar.gz" = "' + "a" * 64 + '"\n', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, r"\[sha256\] table"):
            archive_sha256(manifest, "present.tar.gz")


if __name__ == "__main__":
    unittest.main()
