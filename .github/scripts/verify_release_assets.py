#!/usr/bin/env python3
"""Verify the complete TinySecurity release archive set and its digest manifest."""

import hashlib
import re
import sys
import tomllib
from pathlib import Path


PLATFORMS = {
    "ubuntu-22.04-x86_64",
    "ubuntu-22.04-arm64",
    "ubuntu-24.04-x86_64",
    "ubuntu-24.04-arm64",
    "macos-15-x86_64",
    "macos-15-arm64",
    "macos-26-x86_64",
    "macos-26-arm64",
    "windows-2022-x86_64",
    "windows-2025-x86_64",
    "windows-11-arm64",
    "fedora-43-x86_64",
    "fedora-43-arm64",
    "fedora-44-x86_64",
    "fedora-44-arm64",
    "archlinux-rolling-x86_64",
}
ARCHIVE_NAME = re.compile(r"^tinysecurity-module-(\d+\.\d+\.\d+)-(.+)\.(tar\.gz|zip)$")


def verify_release_assets(directory: Path) -> None:
    archives = sorted((*directory.glob("*.tar.gz"), *directory.glob("*.zip")))
    if len(archives) != len(PLATFORMS):
        raise ValueError(f"expected {len(PLATFORMS)} archives, found {len(archives)}")

    versions = set()
    found_platforms = set()
    for archive in archives:
        match = ARCHIVE_NAME.fullmatch(archive.name)
        if match is None:
            raise ValueError(f"unexpected archive name: {archive.name}")
        version, platform, extension = match.groups()
        expected_extension = "zip" if platform.startswith("windows-") else "tar.gz"
        if extension != expected_extension:
            raise ValueError(f"unexpected archive format for {platform}: {archive.name}")
        versions.add(version)
        found_platforms.add(platform)
    if len(versions) != 1:
        raise ValueError(f"archives contain multiple versions: {sorted(versions)}")
    if found_platforms != PLATFORMS:
        missing = sorted(PLATFORMS - found_platforms)
        unexpected = sorted(found_platforms - PLATFORMS)
        raise ValueError(f"platform set mismatch; missing={missing}, unexpected={unexpected}")

    manifest_path = directory / "checksum.toml"
    try:
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ValueError(f"cannot read checksum manifest: {error}") from error
    checksums = manifest.get("sha256")
    if not isinstance(checksums, dict):
        raise ValueError("checksum.toml must contain a [sha256] table")
    expected_names = {archive.name for archive in archives}
    if set(checksums) != expected_names:
        missing = sorted(expected_names - set(checksums))
        unexpected = sorted(set(checksums) - expected_names)
        raise ValueError(f"checksum archive set mismatch; missing={missing}, unexpected={unexpected}")

    for archive in archives:
        actual = hashlib.sha256(archive.read_bytes()).hexdigest()
        declared = checksums[archive.name]
        if not isinstance(declared, str) or not re.fullmatch(r"[0-9a-f]{64}", declared):
            raise ValueError(f"invalid SHA-256 for {archive.name}")
        if declared != actual:
            raise ValueError(f"SHA-256 mismatch for {archive.name}")


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} RELEASE_ASSET_DIRECTORY", file=sys.stderr)
        return 2
    try:
        verify_release_assets(Path(sys.argv[1]))
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1
    print(f"Verified {len(PLATFORMS)} platform archives against checksum.toml")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
