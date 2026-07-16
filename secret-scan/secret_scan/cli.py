"""CLI entry point for secret_scan."""

import argparse
import sys
import time
from pathlib import Path

from .scanner import scan_directory, scan_file, scan_git_history
from .output import print_banner, print_findings, print_findings_json, print_summary
from .rules import RULES


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secret-scan",
        description="Secrets scanner for codebases and git history · blind-sec",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  secret-scan scan .                    Scan current directory
  secret-scan scan /path/to/repo        Scan specific path
  secret-scan git /path/to/repo         Scan full git history
  secret-scan git . --depth 100         Scan last 100 commits
  secret-scan scan . --format json      Output as JSON
  secret-scan rules                     List all detection rules
        """,
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # ── scan ──────────────────────────────────────────────────────────────────
    scan_p = sub.add_parser("scan", help="Scan a file or directory")
    scan_p.add_argument("path", help="File or directory to scan")
    scan_p.add_argument("--format", choices=["terminal", "json"], default="terminal")
    scan_p.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        default=None, help="Minimum severity to report")
    scan_p.add_argument("--entropy", action="store_true", help="Show entropy scores")
    scan_p.add_argument("--no-color", action="store_true", help="Disable color output")

    # ── git ───────────────────────────────────────────────────────────────────
    git_p = sub.add_parser("git", help="Scan git commit history")
    git_p.add_argument("path", help="Path to git repository")
    git_p.add_argument("--depth", type=int, default=50, help="Number of commits to scan (default: 50)")
    git_p.add_argument("--branch", default="HEAD", help="Branch or ref to start from")
    git_p.add_argument("--format", choices=["terminal", "json"], default="terminal")
    git_p.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=None)
    git_p.add_argument("--no-color", action="store_true")

    # ── rules ─────────────────────────────────────────────────────────────────
    sub.add_parser("rules", help="List all detection rules")

    return parser


def _filter_severity(result, min_severity: str | None):
    if not min_severity:
        return result
    order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    min_rank = order.get(min_severity, 0)
    result.findings = [f for f in result.findings if order.get(f.severity, 0) >= min_rank]
    return result


def cmd_scan(args):
    path = Path(args.path).resolve()
    if not path.exists():
        print(f"[ERROR] Path not found: {path}", file=sys.stderr)
        sys.exit(1)

    if args.format == "terminal":
        print_banner()
        print(f"  Scanning: {path}\n")

    start = time.monotonic()
    if path.is_file():
        result = scan_file(path)
    else:
        result = scan_directory(path)
    elapsed = time.monotonic() - start

    _filter_severity(result, args.severity)

    if args.format == "json":
        print(print_findings_json(result))
    else:
        print_findings(result, no_color=args.no_color, show_entropy=args.entropy)
        print_summary(result, elapsed)

    sys.exit(1 if result.findings else 0)


def cmd_git(args):
    path = Path(args.path).resolve()
    if not (path / ".git").exists() and not (path.name.endswith(".git")):
        print(f"[ERROR] Not a git repository: {path}", file=sys.stderr)
        sys.exit(1)

    if args.format == "terminal":
        print_banner()
        print(f"  Scanning git history: {path}  (depth: {args.depth})\n")

    start = time.monotonic()
    result = scan_git_history(path, branch=args.branch, depth=args.depth)
    elapsed = time.monotonic() - start

    _filter_severity(result, args.severity)

    if args.format == "json":
        print(print_findings_json(result))
    else:
        print_findings(result, no_color=args.no_color)
        print_summary(result, elapsed)

    sys.exit(1 if result.findings else 0)


def cmd_rules(_args):
    print(f"\n  {'ID':<35} {'SERVICE':<18} {'SEVERITY':<10} NAME")
    print("  " + "─" * 85)
    for rule in sorted(RULES, key=lambda r: r.service):
        print(f"  {rule.id:<35} {rule.service:<18} {rule.severity:<10} {rule.name}")
    print(f"\n  Total: {len(RULES)} rules\n")


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "git":
        cmd_git(args)
    elif args.command == "rules":
        cmd_rules(args)


if __name__ == "__main__":
    main()
