"""Behavioral regressions for native coverage report admission."""
import importlib.util
import unittest
import sys
import shlex
import subprocess
import contextlib
import io
import json
import runpy
import tempfile
from unittest import mock
from pathlib import Path

sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location('coverage_gate', Path(__file__).with_name('check-native-coverage.py'))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

WINDOWS = 'crates/tinysecurity-audit/src/windows.rs'
ACL = 'crates/tinysecurity-audit/src/windows_acl.rs'
ADAPTER = 'crates/tinysecurity-module/src/adapter.rs'
COMPILED = {WINDOWS: (1, 1), ACL: (1, 1)}
ROOT = 'D:/a/tinysecurity/tinysecurity'


def report(*entries):
    return {'data': [{'files': [
        {'filename': ROOT + '/' + name, 'summary': {'lines': {'count': count, 'covered': covered}}}
        for name, count, covered in entries
    ]}]}


class NativeCoverageAdmission(unittest.TestCase):
    @contextlib.contextmanager
    def git_coverage_fixture(self, contents):
        """Create actual Git output and reports for one covered changed line."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / WINDOWS
            source.parent.mkdir(parents=True)
            source.write_bytes(b'// initial\n')
            commands = (
                ['init', '--quiet'],
                ['add', 'crates/'],
                ['-c', 'user.name=Coverage Test', '-c', 'user.email=coverage@example.invalid',
                 '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'base'],
            )
            for command in commands:
                subprocess.run(['git', *command], cwd=root, check=True, capture_output=True)
            base = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=root, check=True,
                                  capture_output=True).stdout.decode('ascii').strip()
            source.write_bytes(contents)
            subprocess.run(['git', 'add', 'crates/'], cwd=root, check=True, capture_output=True)
            subprocess.run(['git', '-c', 'user.name=Coverage Test',
                            '-c', 'user.email=coverage@example.invalid',
                            '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'change'],
                           cwd=root, check=True, capture_output=True)
            data = report((WINDOWS, 1, 1), (ACL, 1, 1))
            for entry in data['data'][0]['files']:
                entry['filename'] = str(root / entry['filename'][len(ROOT) + 1:])
            json_path, lcov_path = root / 'coverage.json', root / 'coverage.lcov'
            json_path.write_text(json.dumps(data), encoding='utf-8')
            lcov_path.write_text(''.join(f'SF:{root / name}\nDA:1,1\nend_of_record\n'
                                        for name in (WINDOWS, ACL)), encoding='utf-8')
            yield ['check-native-coverage.py', '--json', str(json_path), '--lcov',
                   str(lcov_path), '--base', base, '--root', str(root)]

    def test_utf8_git_diff_is_measured_under_windows_charmap_locale(self):
        contents = '// caf\u00e9 \u0141\n'.encode('utf-8')
        self.assertIn(b'\x81', contents)
        with self.assertRaises(UnicodeDecodeError):
            contents.decode('cp1252')
        output = io.StringIO()
        with self.git_coverage_fixture(contents) as argv, \
                mock.patch.object(sys, 'argv', argv), \
                mock.patch.object(subprocess, '_text_encoding', return_value='cp1252'), \
                contextlib.redirect_stdout(output):
            # Only the locale default is simulated: main runs real Git and
            # Popen reads its bytes through the actual subprocess path.
            gate.main()
        self.assertIn('Changed executable lines: 1/1 (100.00%)', output.getvalue())
        self.assertNotIn('No changed production', output.getvalue())

    def test_rustdoc_only_changes_skip_changed_executable_line_gate(self):
        output = io.StringIO()
        with self.git_coverage_fixture(b'/// updated documentation\n') as argv, \
                mock.patch.object(sys, 'argv', argv), \
                contextlib.redirect_stdout(output):
            gate.main()
        self.assertIn('No changed compiled executable sources', output.getvalue())
        self.assertNotIn('Changed executable lines:', output.getvalue())

    def test_malformed_utf8_git_diff_is_rejected_instead_of_skipping_changes(self):
        output, errors = io.StringIO(), io.StringIO()
        with self.git_coverage_fixture(b'// invalid \xff\n') as argv, \
                mock.patch.object(sys, 'argv', argv), \
                mock.patch.object(subprocess, '_text_encoding', return_value='cp1252'), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors), \
                self.assertRaises(SystemExit) as failure:
            runpy.run_path(str(Path(gate.__file__)), run_name='__main__')
        self.assertEqual(failure.exception.code, 1)
        self.assertIn('native coverage rejected:', errors.getvalue())
        self.assertIn('utf-8', errors.getvalue())
        self.assertNotIn('No changed production', output.getvalue())
        self.assertNotIn('Changed executable lines:', output.getvalue())

    def test_native_report_command_is_accepted_without_recollecting_tests(self):
        workflow = Path(__file__).parents[1].joinpath('workflows/ci.yml').read_text()
        commands = [shlex.split(line.strip()) for line in workflow.splitlines()
                    if line.strip().startswith('cargo llvm-cov ')]
        self.assertEqual(len(commands), 3, 'collect once, then export JSON and LCOV')
        collection, json_export, lcov_export = commands
        self.assertEqual(collection, [
            'cargo', 'llvm-cov', '--locked', '--workspace', '--all-targets',
            '--all-features', '--no-report',
        ])
        # The native fixtures must add their profiles after collection (which
        # cleans old profiles) and before either export reads that same cohort.
        native = '.github/scripts/run-native-master-cipher-coverage.sh'
        steps = [line.strip() for line in workflow.splitlines()]
        self.assertEqual(steps.count(native), 1)
        self.assertLess(steps.index(shlex.join(collection)), steps.index(native))
        self.assertLess(steps.index(native), steps.index(shlex.join(json_export)))
        for export, format_option, output in (
                (json_export, '--json', 'coverage-native.json'),
                (lcov_export, '--lcov', 'coverage-native.info')):
            with self.subTest(format=format_option):
                # Report-only commands preserve profiles and cannot recollect
                # tests or pass collection-only flags to the reporter.
                self.assertEqual(export, [
                    'cargo', 'llvm-cov', 'report', format_option,
                    '--output-path', output,
                ])
                # Validate the actual reporter's parser, rather than trusting
                # its help table: 0.9.1 lists --all-features there but rejects it.
                parsed = subprocess.run(export + ['--help'], capture_output=True, text=True)
                self.assertEqual(parsed.returncode, 0, parsed.stderr)
                self.assertIn('Generate coverage report', parsed.stdout)

    def test_accepts_native_drive_paths_and_backslashes(self):
        data = report((WINDOWS, 10, 9), (ACL, 10, 10))
        data['data'][0]['files'][0]['filename'] = ('d:/a/tinysecurity/tinysecurity/' + WINDOWS).replace('/', '\\')
        files = gate.check_files(data, ROOT, 90)
        self.assertEqual(files[WINDOWS], (9, 10))

    def test_missing_windows_engine_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'missing.*windows.rs'):
            gate.check_files(report((ACL, 10, 10)), ROOT, 90)

    def test_zero_executable_windows_source_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'executable.*windows.rs'):
            gate.check_files(report((WINDOWS, 0, 0), (ACL, 10, 10)), ROOT, 90)

    def test_low_per_file_coverage_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'below 90'):
            gate.check_files(report((WINDOWS, 10, 8), (ACL, 10, 10)), ROOT, 90)

    def test_checkout_substring_and_path_escape_do_not_admit_sources(self):
        self.assertIsNone(gate.relative_source('X:/other/' + ROOT + '/' + WINDOWS, ROOT))
        with self.assertRaisesRegex(ValueError, 'invalid checkout source path'):
            gate.relative_source(ROOT + '/../outside/' + WINDOWS, ROOT)
        self.assertIsNone(gate.relative_source(ROOT + '-other/' + WINDOWS, ROOT))

    def test_conflicting_duplicate_source_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'conflicting'):
            gate.check_files(report((WINDOWS, 10, 9), (WINDOWS, 10, 10), (ACL, 10, 10)), ROOT, 90)

    def test_lcov_normalizes_windows_paths_and_admits_changed_lines(self):
        lcov = 'SF:' + (ROOT + '/' + WINDOWS).replace('/', '\\') + '\nDA:3,1\nend_of_record\nSF:' + ROOT + '/' + ACL + '\nDA:4,1\nend_of_record\n'
        lines = gate.parse_lcov(lcov, ROOT)
        self.assertEqual(gate.check_changed(lines, {WINDOWS: {3}, ACL: {4}}, 80, COMPILED), (2, 2))

    def test_zero_windows_changed_denominator_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'no measured changed.*windows.rs'):
            gate.check_changed({ACL: {4: 1}}, {WINDOWS: {3}, ACL: {4}}, 80, COMPILED)

    def test_uninstrumented_changed_windows_source_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'no measured changed.*windows_acl.rs'):
            gate.check_changed({WINDOWS: {3: 1}}, {WINDOWS: {3}, ACL: {4}}, 80, COMPILED)

    def test_low_changed_line_coverage_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'below 80'):
            gate.check_changed({WINDOWS: {3: 0}, ACL: {4: 1}}, {WINDOWS: {3}, ACL: {4}}, 80, COMPILED)

    def test_changes_with_no_executable_line_skip_only_changed_line_gate(self):
        # Line 9 of the adapter is a changed constant entry with no LCOV line.
        compiled = {**COMPILED, ADAPTER: (4, 4)}
        lines = {WINDOWS: {3: 1}, ACL: {4: 1}, ADAPTER: {10: 1}}
        self.assertIsNone(gate.check_changed(lines, {ADAPTER: {9}}, 80, compiled))
        # The inventory checks still run first: an uninstrumented source fails.
        with self.assertRaisesRegex(ValueError, 'missing executable LCOV source'):
            gate.check_changed({WINDOWS: {3: 1}, ACL: {4: 1}}, {ADAPTER: {9}}, 80, compiled)

    def test_no_production_changes_skip_only_changed_line_gate(self):
        self.assertIsNone(gate.check_changed({WINDOWS: {3: 1}, ACL: {4: 1}}, {}, 80, COMPILED))
        self.assertEqual(gate.changed_lines('+++ b/crates/a/src/sink_tests.rs\n@@ -0,0 +1 @@\n+x\n'), {})

    def test_missing_lcov_source_fails_even_without_production_changes(self):
        with self.assertRaisesRegex(ValueError, 'executable LCOV lines'):
            gate.check_changed({}, {}, 80, COMPILED)

    def test_unknown_diff_path_is_not_silently_no_changes(self):
        with self.assertRaisesRegex(ValueError, 'unrecognized git diff source path'):
            gate.changed_lines('+++ "b/crates/a/src/unknown.rs"\n@@ -0,0 +1 @@\n+x\n')

    def test_omitted_compiled_adapter_changes_are_rejected(self):
        compiled = {**COMPILED, ADAPTER: (4, 4)}
        with self.assertRaisesRegex(ValueError, 'missing.*LCOV.*adapter.rs'):
            gate.check_changed({WINDOWS: {3: 1}, ACL: {4: 1}},
                               {WINDOWS: {3}, ADAPTER: {100, 101, 102, 103}},
                               80, compiled)

    def test_missing_compiled_lcov_is_rejected_without_changes(self):
        with self.assertRaisesRegex(ValueError, 'missing.*LCOV.*adapter.rs'):
            gate.check_changed({WINDOWS: {3: 1}, ACL: {4: 1}}, {},
                               80, {**COMPILED, ADAPTER: (4, 4)})

    def test_empty_compiled_lcov_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'missing.*LCOV.*adapter.rs'):
            gate.check_changed({WINDOWS: {3: 1}, ACL: {4: 1}, ADAPTER: {}},
                               {ADAPTER: {100}}, 80, {**COMPILED, ADAPTER: (1, 1)})

    def test_uninstrumented_unix_and_declaration_changes_do_not_require_lcov(self):
        unix = 'crates/tinysecurity-audit/src/unix.rs'
        declarations = 'crates/tinysecurity-module/src/lib.rs'
        self.assertEqual(gate.check_changed(
            {WINDOWS: {3: 1}, ACL: {4: 1}},
            {WINDOWS: {3}, unix: {100}, declarations: {1}}, 80,
            {**COMPILED, declarations: (0, 0)}), (1, 1))

    def test_compiled_adapter_uncovered_changes_join_denominator(self):
        with self.assertRaisesRegex(ValueError, 'changed lines: 1/5 below 80'):
            gate.check_changed(
                {WINDOWS: {3: 1}, ACL: {4: 1}, ADAPTER: dict.fromkeys(range(100, 104), 0)},
                {WINDOWS: {3}, ADAPTER: set(range(100, 104))}, 80,
                {**COMPILED, ADAPTER: (90, 100)})

    def test_malformed_checkout_lcov_path_cannot_hide_invalid_data(self):
        with self.assertRaisesRegex(ValueError, 'invalid checkout source path'):
            gate.parse_lcov('SF:' + ROOT + '/crates/a/../src/b.rs\nDA:invalid\n', ROOT)

    def test_malformed_checkout_json_path_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'invalid checkout source path'):
            gate.check_files(report((WINDOWS, 1, 1), (ACL, 1, 1),
                                    ('crates/a/../src/b.rs', 1, 1)), ROOT, 90)

    def test_unknown_checkout_source_path_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'unknown checkout source path'):
            gate.parse_lcov('SF:' + ROOT + '/src/unknown.rs\nDA:1,1\n', ROOT)

    def test_valid_external_and_vendored_dependencies_are_ignored(self):
        lcov = ('SF:C:/cargo/registry/src/lib.rs\nDA:1,1\nend_of_record\n'
                'SF:' + ROOT + '/vendor/dependency/src/lib.rs\nDA:1,1\nend_of_record\n')
        self.assertEqual(gate.parse_lcov(lcov, ROOT), {})

    def test_malformed_checkout_lcov_line_record_is_rejected(self):
        for record in ('DA:1', 'DA:0,1', 'DA:1,-1', 'DA:bad,1'):
            with self.subTest(record=record), self.assertRaises(ValueError):
                gate.parse_lcov('SF:' + ROOT + '/' + WINDOWS + '\n' + record + '\n', ROOT)

    def test_lcov_executable_source_missing_from_json_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'absent from executable JSON.*adapter.rs'):
            gate.check_changed({WINDOWS: {3: 1}, ACL: {4: 1}, ADAPTER: {100: 1}},
                               {ADAPTER: {100}}, 80, COMPILED)

    def test_invalid_checkout_path_components_reject_in_both_reports(self):
        for path in ('crates//a/src/b.rs', 'crates/./a/src/b.rs',
                     'crates/a/src/b\x00.rs'):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'invalid checkout source path'):
                gate.relative_source(ROOT + '/' + path, ROOT)

    def test_unix_platform_requires_native_sink_journal_rotation_and_no_windows_sources(self):
        for platform in ('linux', 'macos'):
            data = report(*((name, 10, 9) for name in gate.UNIX_REQUIRED))
            files = gate.check_files(data, ROOT, 90, platform)
            lines = {name: {3: 1} for name in gate.UNIX_REQUIRED}
            self.assertEqual(gate.check_changed(lines, {gate.UNIX_REQUIRED[0]: {3}}, 80, files, platform), (1, 1))
            self.assertNotIn(WINDOWS, files)
            with self.assertRaisesRegex(ValueError, 'missing required.*sink.rs'):
                gate.check_files(report(*((name, 10, 10) for name in gate.UNIX_REQUIRED[1:])), ROOT, 90, platform)

    def test_unix_native_coverage_rejects_low_files_and_missing_compiled_inventory(self):
        for platform in ('linux', 'macos'):
            data = report(*((name, 10, 10) for name in gate.UNIX_REQUIRED), (ADAPTER, 10, 8))
            with self.assertRaisesRegex(ValueError, 'below 90'):
                gate.check_files(data, ROOT, 90, platform)
            files = {name: (10, 10) for name in gate.UNIX_REQUIRED}
            lines = {name: {3: 1} for name in gate.UNIX_REQUIRED}
            with self.assertRaisesRegex(ValueError, 'missing.*LCOV.*adapter.rs'):
                gate.check_changed(lines, {}, 80, {**files, ADAPTER: (1, 1)}, platform)
            with self.assertRaisesRegex(ValueError, 'absent from executable JSON.*adapter.rs'):
                gate.check_changed({**lines, ADAPTER: {3: 1}}, {}, 80, files, platform)

    def test_unix_uncovered_changes_join_the_eighty_percent_denominator(self):
        for platform in ('linux', 'macos'):
            files = {name: (10, 10) for name in gate.UNIX_REQUIRED}
            lines = {name: {3: 1} for name in gate.UNIX_REQUIRED}
            lines[ADAPTER] = dict.fromkeys(range(100, 104), 0)
            with self.assertRaisesRegex(ValueError, 'changed lines: 1/5 below 80'):
                gate.check_changed(lines, {gate.UNIX_REQUIRED[0]: {3}, ADAPTER: set(range(100, 104))}, 80, {**files, ADAPTER: (90, 100)}, platform)

    def test_changes_only_to_platform_disabled_sources_do_not_create_a_fake_denominator(self):
        self.assertIsNone(gate.check_changed({WINDOWS: {3: 1}, ACL: {4: 1}},
                                            {'crates/tinysecurity-audit/src/unix.rs': {100}},
                                            80, COMPILED))
        for platform in ('linux', 'macos'):
            files = {name: (1, 1) for name in gate.UNIX_REQUIRED}
            lines = {name: {3: 1} for name in gate.UNIX_REQUIRED}
            self.assertIsNone(gate.check_changed(lines, {WINDOWS: {100}}, 80, files, platform))

    def test_added_and_modified_line_ranges_come_from_zero_context_diff(self):
        diff = '+++ b/' + WINDOWS + '\n@@ -1,2 +3,2 @@\n+x\n+y\n+++ b/' + ACL + '\n@@ -0,0 +4 @@\n+z\n'
        self.assertEqual(gate.changed_lines(diff), {WINDOWS: {3, 4}, ACL: {4}})


if __name__ == '__main__':
    unittest.main()
