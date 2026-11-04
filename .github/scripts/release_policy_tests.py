"""Verify which repository/ref pairs may enter the release job."""

import ast
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]


def prepare_guard():
    workflow = (ROOT / ".github/workflows/release.yml").read_text()
    job = re.search(r"(?ms)^  prepare:\n(.*?)(?=^  [\w-]+:\n|\Z)", workflow)
    if job is None:
        raise ValueError("release prepare job is missing")
    conditions = re.findall(r"^    if:\s*(.+)$", job[1], re.MULTILINE)
    if len(conditions) != 1:
        raise ValueError("release prepare job must have one authorization condition")
    condition = conditions[0].removeprefix("${{").removesuffix("}}")
    return ast.parse(condition.replace("&&", " and ").replace("||", " or ").strip(), mode="eval").body


def allows(node, repository, ref):
    """Interpret only the equality/boolean subset used by this policy."""
    if isinstance(node, ast.BoolOp):
        values = [allows(value, repository, ref) for value in node.values]
        if isinstance(node.op, ast.And):
            return all(values)
        if isinstance(node.op, ast.Or):
            return any(values)
    if isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq):
        return allows(node.left, repository, ref) == allows(node.comparators[0], repository, ref)
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "github":
        if node.attr == "repository":
            return repository
        if node.attr == "ref":
            return ref
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    raise ValueError("release guard contains an unsupported policy expression")


class ReleasePolicyTests(unittest.TestCase):
    def test_only_canonical_main_can_prepare_a_release(self):
        guard = prepare_guard()
        for repository in ["tinyhumansai/tinysecurity", "senamakel/tinysecurity"]:
            for ref in ["refs/heads/main", "refs/heads/epic/8369-security-migration", "refs/pull/49/merge"]:
                with self.subTest(repository=repository, ref=ref):
                    expected = repository == "tinyhumansai/tinysecurity" and ref == "refs/heads/main"
                    self.assertEqual(allows(guard, repository, ref), expected)


class ReleaseModuleLinkTests(unittest.TestCase):
    def test_release_builds_leave_the_dbus_keyring_off(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        # The prepare job still tests with --all-features and so needs libdbus-1-dev;
        # only the jobs that build the shipped library are held to this.
        bundles = workflow[workflow.index("\n  native-bundles:") :]
        self.assertNotIn("--features", bundles)
        self.assertNotIn("libdbus", bundles)
        self.assertNotIn("dbus-devel", bundles)

    def test_every_linux_release_build_checks_needed_libraries(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertEqual(workflow.count("check-module-needed-libs.sh"), 2)


if __name__ == "__main__":
    unittest.main()
