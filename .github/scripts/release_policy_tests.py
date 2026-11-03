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


if __name__ == "__main__":
    unittest.main()
