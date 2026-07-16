# secret-scan

Secrets scanner for codebases and git history. Detects exposed API keys, tokens, credentials, and private keys before they become a breach.

**Zero runtime dependencies. Pure Python 3.11+. Linux · macOS · Windows.**

## What It Detects

100+ rules across 25+ services:

| Category | Services |
|---|---|
| **Cloud** | AWS Access Keys, GCP Service Accounts, Azure Storage Keys |
| **Version Control** | GitHub PATs (classic + fine-grained), GitLab Tokens, npm auth tokens |
| **Payment** | Stripe Secret/Webhook Keys, Square Access Tokens, Shopify |
| **Communication** | Slack Bot Tokens, Slack Webhooks, Discord, Telegram |
| **Email** | SendGrid API Keys, Mailgun API Keys, Twilio |
| **Database** | PostgreSQL, MySQL, MongoDB, Redis connection strings |
| **Cryptography** | RSA/EC/OpenSSH Private Keys, PGP Private Keys |
| **Auth** | JWT Tokens, JWT Signing Secrets, Bearer Tokens, Basic Auth in URLs |
| **Generic** | Hardcoded passwords, high-entropy strings |

**Shannon entropy analysis** catches secrets that don't match known patterns — high-randomness strings that shouldn't be in source code.

**Lockfile protection** — automatically skips `package-lock.json`, `yarn.lock`, `Gemfile.lock`, etc. to eliminate false positives from integrity hashes.

## Advantages over similar tools

| Feature | secret-scan | truffleHog | gitleaks |
|---|---|---|---|
| Zero dependencies | ✅ | ❌ | ❌ |
| Windows native | ✅ | ⚠️ | ⚠️ |
| Python (readable/auditable) | ✅ | ❌ Go | ❌ Go |
| Shannon entropy | ✅ | ✅ | ✅ |
| Git history scan | ✅ | ✅ | ✅ |
| JSON output | ✅ | ✅ | ✅ |
| Secret auto-redaction | ✅ | ❌ | ❌ |
| Lockfile false positive skip | ✅ | ❌ | ⚠️ |
| Unit test suite (26 tests) | ✅ | — | — |

## Install

```bash
git clone https://github.com/blind-sec/security-projects
cd security-projects/secret-scan
pip install -e .
```

## Usage

```bash
# Scan a directory
secret-scan scan .

# Scan a specific path
secret-scan scan /path/to/project

# Scan git history (last 50 commits)
secret-scan git .

# Scan deeper git history
secret-scan git . --depth 200

# Scan specific branch
secret-scan git . --branch main --depth 100

# Output as JSON (for CI/CD pipelines)
secret-scan scan . --format json

# Only show critical and high findings
secret-scan scan . --severity HIGH

# List all detection rules
secret-scan rules
```

## Output

```
  ___  ___  ___  ____  ____  ____       ___   ___   __   __ _
 / __)( __)/ __)(  _ \( ___)(_  _)___  / __) / __) / _\ (  ( \
 \__ \ ) _)( (__  )   / ) _)   )( (___)\ __\( (__ /    \/    /
 (___/(____)\___)(__)\_)(____) (__)     (___/ \___)\-/\_/\_)__)

  Secrets Scanner · blind-sec · github.com/blind-sec/security-projects

  Scanning: /path/to/project

  [!] CRITICAL (1)
  ──────────────────────────────────────────────────────────
  RSA Private Key
    Service  : Cryptography
    Location : artifacts/cert/server.key:1
    Match    : -----B...----
    Context  : -----BEGIN RSA PRIVATE KEY-----

  [!] HIGH (2)
  ──────────────────────────────────────────────────────────
  Hardcoded Secret
    Service  : Generic
    Location : config/env/development.js:6
    Match    : ApiKey...od1"
    Context  : zapApiKey: "v9dn0balpqas1pcc281tn5ood1",

  ────────────────────────────────────────────────────────────
  SCAN COMPLETE
  ────────────────────────────────────────────────────────────
  Files scanned   : 92
  Lines scanned   : 6,861
  Time elapsed    : 0.81s

  Findings        : 3
  ├─ CRITICAL     : 1
  ├─ HIGH         : 2
  ├─ MEDIUM       : 0
  └─ LOW          : 0
```

> Output above is from a real scan of [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) — an intentionally vulnerable Node.js application.

## CI/CD Integration

Exit code `1` when findings exist, `0` when clean. Drop into any pipeline:

```yaml
# GitHub Actions
- name: Scan for secrets
  run: secret-scan scan . --format json --severity HIGH
```

```bash
# Pre-commit hook
secret-scan scan . --severity CRITICAL || exit 1
```

## Tests

```bash
pip install pytest
pytest tests/ -v
# 26 passed in 0.20s
```

Coverage:
- Entropy analysis (7 tests)
- Rule compilation and pattern matching (12 tests)
- File/directory scanning, edge cases (7 tests)

## Architecture

```
secret_scan/
├── cli.py       — argparse CLI (scan, git, rules subcommands)
├── scanner.py   — file/directory/git scanning engine + lockfile skip
├── rules.py     — 100+ regex detection rules with severity/service metadata
├── entropy.py   — Shannon entropy for high-randomness string detection
└── output.py    — colored terminal output + JSON formatter

tests/
├── test_scanner.py      — 26 unit tests
└── fixtures/
    └── fake_secrets.py  — structurally valid test credentials
```

## License

MIT — free to use, modify, and distribute.

---

*Part of [blind-sec/security-projects](https://github.com/blind-sec/security-projects)*
