#!/usr/bin/env python3
"""Enforce native file and changed-line coverage without dependencies.

JSON supplies per-file executable counts; LCOV supplies changed executable lines.
Only exact checkout-relative crate paths are admitted. Both Windows audit sources
must be instrumented on Windows; Unix runners require the native journal and sink.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

REQUIRED = (
    'crates/tinysecurity-audit/src/windows.rs',
    'crates/tinysecurity-audit/src/windows_acl.rs',
)

UNIX_REQUIRED = (
    'crates/tinysecurity-audit/src/sink.rs',
    'crates/tinysecurity-audit/src/journal.rs',
    'crates/tinysecurity-audit/src/rotation.rs',
)


def required_sources(platform):
    """Select actual native sources, never require disabled Windows code on Unix."""
    return REQUIRED if platform == 'windows' else UNIX_REQUIRED


def relative_source(filename, root):
    """Return a crate path under the exact checkout, or None for other files."""
    filename = filename.replace('\\', '/')
    root = root.replace('\\', '/').rstrip('/')
    # Windows drive paths are case insensitive; POSIX paths are not.
    windows = bool(re.match(r'^[A-Za-z]:/', root))
    candidate = filename.casefold() if windows else filename
    prefix = (root.casefold() if windows else root) + '/'
    if not candidate.startswith(prefix):
        return None
    relative = filename[len(prefix):]
    if windows:
        relative = relative.casefold()
    parts = relative.split('/')
    if '\x00' in relative or any(part in ('', '.', '..') for part in parts):
        raise ValueError(f'invalid checkout source path: {filename}')
    if relative.startswith('vendor/'):
        return None
    if not relative.startswith('crates/') or not relative.endswith('.rs'):
        raise ValueError(f'unknown checkout source path: {filename}')
    return relative


def check_files(report, root, minimum, platform="windows"):
    """Reject absent, empty, inconsistent, or below-threshold source reports."""
    files = {}
    for datum in report['data']:
        for entry in datum['files']:
            name = relative_source(entry['filename'], root)
            if name is None:
                continue
            lines = entry['summary']['lines']
            count, covered = lines['count'], lines['covered']
            if (type(count) is not int or type(covered) is not int
                    or count < 0 or covered < 0 or covered > count):
                raise ValueError(f'invalid executable counts: {name}')
            counts = (covered, count)
            if name in files and files[name] != counts:
                raise ValueError(f'conflicting duplicate source: {name}')
            files[name] = counts
    for name in required_sources(platform):
        if name not in files:
            raise ValueError(f'missing required {platform.title()} source: {name}')
        if files[name][1] == 0:
            raise ValueError(f'no executable lines in required {platform.title()} source: {name}')
    for name, (covered, count) in sorted(files.items()):
        if count and covered * 100 < minimum * count:
            raise ValueError(f'{name}: {covered}/{count} lines below {minimum}%')
    return files


def parse_lcov(report, root):
    """Normalize LCOV SF records and merge repeated instrumentation counts."""
    files = {}
    current = None
    for record in report.splitlines():
        if record.startswith('SF:'):
            current = relative_source(record[3:], root)
            if current is not None:
                files.setdefault(current, {})
        elif record.startswith('DA:') and current is not None:
            fields = record[3:].split(',')
            if len(fields) not in (2, 3):
                raise ValueError(f'invalid LCOV line record: {current}')
            line, count = int(fields[0]), int(fields[1])
            if line <= 0 or count < 0:
                raise ValueError(f'invalid LCOV line: {current}')
            files[current][line] = files[current].get(line, 0) + count
        elif record == 'end_of_record':
            current = None
    return files


def production_source(name):
    """Tests are not production changes; their JSON file coverage still applies."""
    return (name.startswith('crates/') and '/src/' in name
            and name.endswith('.rs') and not name.endswith('_tests.rs'))


def changed_lines(diff):
    """Extract changed executable production lines from git's unified=0 diff."""
    files = {}
    current = None
    new_line = None
    remaining = 0
    for line in diff.splitlines():
        if line.startswith('+++ '):
            name = line[4:]
            if not name.startswith('b/') and name != '/dev/null':
                raise ValueError('unrecognized git diff source path')
            current = name[2:] if name.startswith('b/') else None
            if current is not None and any(part in ('', '.', '..') for part in current.split('/')):
                raise ValueError('invalid git diff source path')
            if current is not None and not production_source(current):
                current = None
            new_line = None
            remaining = 0
        elif current is not None and line.startswith('@@ '):
            match = re.match(r'@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@', line)
            if match is None:
                raise ValueError('invalid git diff hunk')
            new_line = int(match[1])
            remaining = int(match[2]) if match[2] is not None else 1
        elif current is not None and new_line is not None and remaining:
            if line.startswith('+') and not line.startswith('+++'):
                source = line[1:].lstrip()
                # Rustdoc comments do not compile to executable lines. In
                # particular, documentation-only changes must not fail the
                # changed-line gate for having no measured executable lines.
                if not source.startswith(('///', '//!')):
                    files.setdefault(current, set()).add(new_line)
                new_line += 1
                remaining -= 1
            elif line.startswith('-') and not line.startswith('---'):
                continue
            elif line.startswith(' '):
                new_line += 1
                remaining -= 1
    return files


def check_changed(lines, changed, minimum, compiled, platform="windows"):
    """Cross-check compiled production admission before measuring changed lines.

    JSON is the native compilation inventory: platform-disabled sources are
    absent, and declaration-only sources have zero executable lines. Neither
    requires LCOV. Every admitted executable production source does, even when
    unchanged, so missing instrumentation cannot silently shrink the gate.
    """
    for name in required_sources(platform):
        if not lines.get(name):
            raise ValueError(f'no measured changed or executable LCOV lines: {name}')
    for name, (_, count) in compiled.items():
        if production_source(name) and count and not lines.get(name):
            raise ValueError(f'missing executable LCOV source: {name}')
    for name, executable in lines.items():
        if production_source(name) and executable and (name not in compiled or not compiled[name][1]):
            raise ValueError(f'LCOV source absent from executable JSON inventory: {name}')
    # Sources disabled on this platform and declaration-only files supply no
    # executable denominator. Inventory consistency above still runs first.
    changed = {name: changed_set for name, changed_set in changed.items()
               if name in compiled and compiled[name][1]}
    if not changed:
        return None
    for name in required_sources(platform):
        if name not in changed:
            continue
        measured = set(lines.get(name, {})) & changed.get(name, set())
        if not measured:
            raise ValueError(f'no measured changed executable lines: {name}')
    covered = total = 0
    for name, changed_set in changed.items():
        for line in changed_set & set(lines.get(name, {})):
            total += 1
            covered += lines[name][line] > 0
    if not total:
        # Every changed line is non-executable (a constant table entry, a
        # plain comment, an attribute): there is nothing to measure. Required
        # platform sources were checked above, and every executable source
        # still needs LCOV, so this cannot hide missing instrumentation.
        return None
    if covered * 100 < minimum * total:
        raise ValueError(f'changed lines: {covered}/{total} below {minimum}%')
    return covered, total


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--json', required=True)
    parser.add_argument('--lcov', required=True)
    parser.add_argument('--base', required=True, help='canonical PR base commit/ref')
    parser.add_argument('--root', default=str(Path.cwd()))
    parser.add_argument('--platform', choices=('windows', 'linux', 'macos'), default='windows')
    args = parser.parse_args()
    files = check_files(json.loads(Path(args.json).read_text(encoding='utf-8')), args.root, 90, args.platform)
    print('File\tLine coverage\tCovered lines\tCoverable lines')
    for name, (covered, count) in sorted(files.items()):
        if count:
            print(f'{name}\t{covered * 100 / count:.2f}%\t{covered}\t{count}')
    # Decode after byte capture: Windows text-reader threads can lose stdout
    # on a decoding failure. Strict UTF-8 errors must reject the gate instead.
    diff = subprocess.run(
        ['git', '-c', 'core.quotePath=false', 'diff', '--no-ext-diff', '--no-renames',
         '--unified=0', args.base, 'HEAD', '--', 'crates/'],
        cwd=args.root, check=True, capture_output=True,
    ).stdout.decode('utf-8')
    changed = changed_lines(diff)
    lcov = parse_lcov(Path(args.lcov).read_text(encoding='utf-8'), args.root)
    result = check_changed(lcov, changed, 80, files, args.platform)
    if result is None:
        print('No changed compiled executable sources relative to canonical base; file gate passed.')
        return
    covered, total = result
    print(f'Changed executable lines: {covered}/{total} ({covered * 100 / total:.2f}%)')
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as summary:
            summary.write(f'Native {args.platform} coverage: {len(files)} source reports; '
                          f'changed executable lines {covered}/{total}.\n')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        print(f'native coverage rejected: {error}', file=sys.stderr)
        sys.exit(1)
