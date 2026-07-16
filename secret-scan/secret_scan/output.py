"""Terminal output and JSON formatting for secret_scan findings."""

import json
import sys
from datetime import datetime

from .scanner import Finding, ScanResult

# ANSI color codes (no external dependency)
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[91m"
ORANGE = "\033[93m"
YELLOW = "\033[33m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
GREY   = "\033[90m"
WHITE  = "\033[97m"


SEVERITY_COLOR = {
    "CRITICAL": RED,
    "HIGH":     ORANGE,
    "MEDIUM":   YELLOW,
    "LOW":      CYAN,
}

SEVERITY_ICON = {
    "CRITICAL": "●",
    "HIGH":     "●",
    "MEDIUM":   "◉",
    "LOW":      "○",
}


def _supports_color() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _c(text: str, *codes: str) -> str:
    if not _supports_color():
        return text
    return "".join(codes) + text + RESET


def print_banner():
    banner = r"""
  ___  ___  ___  ____  ____  ____       ___   ___   __   __ _
 / __)( __)/ __)(  _ \( ___)(_  _)___  / __) / __) / _\ (  ( \
 \__ \ ) _)( (__  )   / ) _)   )( (___)\__ \( (__ /    \/    /
 (___/(____)\___)(__)\_)(____) (__)     (___/ \___)\_/\_/\_)__)
    """
    print(_c(banner, CYAN, BOLD))
    print(_c("  Secrets Scanner · blind-sec · github.com/blind-sec/security-projects\n", GREY))


def print_summary(result: ScanResult, elapsed: float):
    total = len(result.findings)
    crit  = len(result.critical)
    high  = len(result.high)
    med   = len(result.medium)
    low   = len(result.low)

    print()
    print(_c("─" * 60, GREY))
    print(_c(f"  SCAN COMPLETE", BOLD, WHITE))
    print(_c("─" * 60, GREY))
    print(f"  Files scanned   : {_c(str(result.files_scanned), CYAN)}")
    print(f"  Lines scanned   : {_c(str(result.lines_scanned), CYAN)}")
    print(f"  Time elapsed    : {_c(f'{elapsed:.2f}s', CYAN)}")
    print()
    print(f"  Findings        : {_c(str(total), BOLD, RED if total else GREEN)}")
    if total:
        print(f"  ├─ CRITICAL     : {_c(str(crit), RED)}")
        print(f"  ├─ HIGH         : {_c(str(high), ORANGE)}")
        print(f"  ├─ MEDIUM       : {_c(str(med), YELLOW)}")
        print(f"  └─ LOW          : {_c(str(low), CYAN)}")
    else:
        print(_c("  No secrets found.", GREEN))
    print(_c("─" * 60, GREY))
    if result.errors:
        print(_c(f"\n  Warnings ({len(result.errors)}):", YELLOW))
        for err in result.errors[:5]:
            print(_c(f"    ! {err}", YELLOW))
    print()


def print_findings(result: ScanResult, no_color: bool = False, show_entropy: bool = False):
    if not result.findings:
        return

    # Group by severity
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        bucket = [f for f in result.findings if f.severity == severity]
        if not bucket:
            continue
        color = SEVERITY_COLOR[severity]
        icon  = SEVERITY_ICON[severity]
        print(_c(f"\n  {icon} {severity} ({len(bucket)})", BOLD, color))
        print(_c("  " + "─" * 58, GREY))
        for finding in bucket:
            _print_finding(finding, color, show_entropy)


def _print_finding(f: Finding, color: str, show_entropy: bool):
    loc = f"{f.file}:{f.line_number}"
    if f.commit:
        loc += f"  [commit: {f.commit}  {f.author}  {f.date}]"

    print(f"  {_c(f.rule_name, BOLD, color)}")
    print(f"    {_c('Service  :', GREY)} {f.service}")
    print(f"    {_c('Location :', GREY)} {_c(loc, WHITE)}")
    print(f"    {_c('Match    :', GREY)} {_c(f.redacted_match, ORANGE)}")
    if show_entropy and f.entropy:
        print(f"    {_c('Entropy  :', GREY)} {f.entropy:.2f}")
    # Show surrounding context (truncated)
    ctx = f.line_content.strip()[:120]
    print(f"    {_c('Context  :', GREY)} {_c(ctx, DIM)}")
    print()


def print_findings_json(result: ScanResult) -> str:
    output = {
        "scan_time": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "total":    len(result.findings),
            "critical": len(result.critical),
            "high":     len(result.high),
            "medium":   len(result.medium),
            "low":      len(result.low),
            "files_scanned": result.files_scanned,
            "lines_scanned": result.lines_scanned,
        },
        "findings": [
            {
                "rule_id":      f.rule_id,
                "rule_name":    f.rule_name,
                "severity":     f.severity,
                "service":      f.service,
                "file":         f.file,
                "line":         f.line_number,
                "match":        f.redacted_match,
                "entropy":      f.entropy,
                "commit":       f.commit,
                "author":       f.author,
                "date":         f.date,
            }
            for f in result.findings
        ],
        "errors": result.errors,
    }
    return json.dumps(output, indent=2)
