"""Small, real Autopcp MVP scanner for Python repositories.

Uses Python's stdlib AST parser and deterministic rules. It is intentionally
local-only: scanned source is never executed or sent anywhere.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path


SECRET_NAME = re.compile(r"(password|passwd|secret|api[_-]?key|token|private[_-]?key)", re.I)


@dataclass
class Finding:
    id: str
    title: str
    file: str
    line: int
    category: str
    severity: str
    cwe: str | None
    message: str


class Visitor(ast.NodeVisitor):
    def __init__(self, path: Path, source: str):
        self.path = str(path)
        self.source = source
        self.findings: list[Finding] = []

    def add(self, rule: str, title: str, node: ast.AST, category: str, severity: str, cwe: str | None, message: str):
        self.findings.append(Finding(rule, title, self.path, getattr(node, "lineno", 1), category, severity, cwe, message))

    def visit_Call(self, node: ast.Call):
        name = ""
        if isinstance(node.func, ast.Name):
            name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            name = node.func.attr

        if name in {"eval", "exec"}:
            self.add("SEC-PY-001", f"Use of {name}()", node, "security", "high", "CWE-95", f"{name}() can execute attacker-controlled Python code.")
        if name == "run" and any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
            self.add("SEC-PY-002", "Subprocess called with shell=True", node, "security", "high", "CWE-78", "Shell interpretation can turn untrusted input into arbitrary command execution.")
        if name in {"loads", "load"} and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle":
            self.add("SEC-PY-003", "Unsafe pickle deserialization", node, "security", "high", "CWE-502", "Pickle can instantiate arbitrary objects when loading untrusted bytes.")
        if name == "load" and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "yaml":
            safe = any(k.arg == "Loader" and isinstance(k.value, ast.Attribute) and k.value.attr == "SafeLoader" for k in node.keywords)
            if not safe:
                self.add("SEC-PY-004", "Unsafe YAML load", node, "security", "medium", "CWE-502", "Use yaml.safe_load or SafeLoader for untrusted YAML.")
        if name in {"md5", "sha1"}:
            self.add("SEC-PY-005", f"Weak hash {name}()", node, "security", "medium", "CWE-327", "MD5 and SHA-1 are unsuitable for password or security-sensitive hashing.")
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name) and SECRET_NAME.search(target.id) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) and len(node.value.value) >= 6:
                self.add("SEC-PY-006", "Possible hardcoded secret", node, "security", "high", "CWE-798", "Move credentials to environment variables or a secret manager.")
        self.generic_visit(node)

    def visit_Module(self, node: ast.Module):
        if not ast.get_docstring(node):
            self.add("STY-PY-001", "Missing module docstring", node, "style", "low", None, "Add a short module-level docstring describing this module.")
        self.generic_visit(node)


def scan_file(path: Path, root: Path) -> list[Finding]:
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except UnicodeDecodeError:
        return []
    except SyntaxError as exc:
        return [Finding("PARSE-PY-001", "Python syntax error", str(path), exc.lineno or 1, "style", "high", None, exc.msg)]
    findings = Visitor(path.relative_to(root), source)
    findings.visit(tree)
    for line_no, line in enumerate(source.splitlines(), 1):
        if len(line) > 100:
            findings.findings.append(Finding("STY-PY-002", "Line exceeds 100 characters", str(path.relative_to(root)), line_no, "style", "low", None, f"This line is {len(line)} characters long."))
    return findings.findings


def scan(target: Path) -> dict:
    target = target.resolve()
    root = target if target.is_dir() else target.parent
    files = [target] if target.is_file() else sorted(target.rglob("*.py"))
    findings = [finding for path in files for finding in scan_file(path, root)]
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return {"target": str(target), "files_scanned": len(files), "findings": [asdict(f) for f in findings], "summary": counts}


def main():
    parser = argparse.ArgumentParser(description="Scan Python files with Autopcp's deterministic AST rules.")
    parser.add_argument("path", nargs="?", default=".", help="Python file or repository directory")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    args = parser.parse_args()
    result = scan(Path(args.path))
    if args.json:
        print(json.dumps(result, indent=2))
        return
    print(f"Autopcp scan: {result['target']}")
    print(f"Files scanned: {result['files_scanned']}  Findings: {len(result['findings'])}")
    print("  " + "  ".join(f"{key}: {value}" for key, value in result["summary"].items()))
    for finding in result["findings"]:
        print(f"{finding['severity'].upper():8} {finding['id']:12} {finding['file']}:{finding['line']} — {finding['title']}")


if __name__ == "__main__":
    main()
