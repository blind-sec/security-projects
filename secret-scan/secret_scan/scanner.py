"""Core scanning engine for secret_scan."""

import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from .rules import RULES, ALLOWLISTED_PATHS, STOPWORDS, Rule
from .entropy import find_high_entropy_base64, find_high_entropy_hex, is_high_entropy


# File extensions to skip (binary/media)
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".mp4", ".mp3", ".wav", ".avi", ".mov", ".mkv",
    ".zip", ".tar", ".gz", ".7z", ".rar", ".bz2",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".obj",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".pyc", ".pyo", ".class", ".jar",
    ".ttf", ".woff", ".woff2", ".eot",
    ".db", ".sqlite", ".sqlite3",
}

# File names to skip entirely (lockfiles contain hashes that trigger false positives)
SKIP_FILENAMES = {
    "package-lock.json", "yarn.lock", "composer.lock",
    "Gemfile.lock", "poetry.lock", "Pipfile.lock",
    "pnpm-lock.yaml", "bun.lockb",
}

MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: str
    service: str
    file: str
    line_number: int
    line_content: str
    match: str
    entropy: float = 0.0
    commit: str = ""        # populated during git scanning
    author: str = ""
    date: str = ""

    @property
    def redacted_match(self) -> str:
        """Show only first 6 and last 4 chars of the secret."""
        m = self.match.strip()
        if len(m) <= 12:
            return "***REDACTED***"
        return f"{m[:6]}...{m[-4:]}"


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    lines_scanned: int = 0
    errors: list[str] = field(default_factory=list)

    def add(self, finding: Finding):
        self.findings.append(finding)

    @property
    def critical(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "CRITICAL"]

    @property
    def high(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "HIGH"]

    @property
    def medium(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "MEDIUM"]

    @property
    def low(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "LOW"]


def _should_skip_path(path: Path) -> bool:
    """Return True if this path should be excluded from scanning."""
    for part in path.parts:
        if part in ALLOWLISTED_PATHS:
            return True
    return False


def _should_skip_file(path: Path) -> bool:
    """Return True if this specific file should be skipped."""
    return path.name in SKIP_FILENAMES


def _is_binary(path: Path) -> bool:
    return path.suffix.lower() in BINARY_EXTENSIONS


def _contains_stopword(value: str) -> bool:
    v = value.lower()
    return any(sw in v for sw in STOPWORDS)


def _scan_line(line: str, line_number: int, filepath: str, rules: list[Rule]) -> list[Finding]:
    findings = []
    for rule in rules:
        pattern = rule.compiled()
        for match in pattern.finditer(line):
            matched_text = match.group(0)
            # Skip obvious placeholders
            if _contains_stopword(matched_text):
                continue
            entropy = 0.0
            if rule.entropy_check:
                entropy = 0.0
                import math, collections
                if matched_text:
                    counts = collections.Counter(matched_text)
                    length = len(matched_text)
                    entropy = -sum((c/length)*math.log2(c/length) for c in counts.values())
                if entropy < rule.min_entropy:
                    continue
            findings.append(Finding(
                rule_id=rule.id,
                rule_name=rule.name,
                severity=rule.severity,
                service=rule.service,
                file=filepath,
                line_number=line_number,
                line_content=line.rstrip()[:200],
                match=matched_text,
                entropy=round(entropy, 2),
            ))
    return findings


def scan_file(path: Path, rules: list[Rule] | None = None) -> ScanResult:
    """Scan a single file for secrets."""
    if rules is None:
        rules = RULES
    result = ScanResult()
    if _is_binary(path):
        return result
    if _should_skip_file(path):
        return result
    if path.stat().st_size > MAX_FILE_SIZE_BYTES:
        result.errors.append(f"Skipped (too large): {path}")
        return result
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, start=1):
                result.lines_scanned += 1
                findings = _scan_line(line, lineno, str(path), rules)
                for f in findings:
                    result.add(f)
        result.files_scanned = 1
    except PermissionError:
        result.errors.append(f"Permission denied: {path}")
    except Exception as e:
        result.errors.append(f"Error reading {path}: {e}")
    return result


def scan_directory(root: Path, rules: list[Rule] | None = None) -> ScanResult:
    """Recursively scan a directory for secrets."""
    if rules is None:
        rules = RULES
    combined = ScanResult()
    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        if _should_skip_path(current.relative_to(root) if current != root else current):
            dirnames.clear()
            continue
        # Prune allowlisted dirs in-place so os.walk skips them
        dirnames[:] = [d for d in dirnames if d not in ALLOWLISTED_PATHS]
        for filename in filenames:
            filepath = current / filename
            if _should_skip_path(filepath):
                continue
            if _should_skip_file(filepath):
                continue
            file_result = scan_file(filepath, rules)
            combined.findings.extend(file_result.findings)
            combined.files_scanned += file_result.files_scanned
            combined.lines_scanned += file_result.lines_scanned
            combined.errors.extend(file_result.errors)
    return combined


def scan_git_history(repo_path: Path, rules: list[Rule] | None = None,
                     branch: str = "HEAD", depth: int = 50) -> ScanResult:
    """
    Scan git commit history for secrets.
    Checks each commit's diff for pattern matches.
    """
    if rules is None:
        rules = RULES
    result = ScanResult()

    try:
        # Get list of commits
        log_cmd = [
            "git", "-C", str(repo_path), "log",
            "--format=%H|%ae|%ai", f"-{depth}", branch
        ]
        log_output = subprocess.check_output(log_cmd, stderr=subprocess.DEVNULL, text=True)
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        result.errors.append(f"Git log failed: {e}")
        return result

    commits = []
    for line in log_output.strip().splitlines():
        parts = line.split("|", 2)
        if len(parts) == 3:
            commits.append({"hash": parts[0], "author": parts[1], "date": parts[2]})

    for commit in commits:
        try:
            diff_cmd = [
                "git", "-C", str(repo_path), "show",
                "--unified=0", "--no-color", commit["hash"]
            ]
            diff = subprocess.check_output(diff_cmd, stderr=subprocess.DEVNULL, text=True, errors="replace")
        except subprocess.CalledProcessError:
            continue

        current_file = f"[git:{commit['hash'][:8]}]"
        for lineno, line in enumerate(diff.splitlines(), start=1):
            # Only scan added lines
            if not line.startswith("+") or line.startswith("+++"):
                continue
            if line.startswith("+++ b/"):
                current_file = line[6:]
                continue
            clean_line = line[1:]  # strip leading +
            findings = _scan_line(clean_line, lineno, current_file, rules)
            for f in findings:
                f.commit = commit["hash"][:8]
                f.author = commit["author"]
                f.date = commit["date"][:10]
                result.add(f)

    return result
