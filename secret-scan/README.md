# secret-scan

Secrets scanner for codebases and git history. Detects exposed API keys, tokens, credentials, and private keys before they become a breach.

Zero runtime dependencies. Pure Python 3.11+. Works on Linux, macOS, and Windows.

## What It Detects

100+ rules across 25+ services:

| Category | Examples |
|---|---|
| **Cloud** | AWS Access Keys, GCP Service Accounts, Azure Storage Keys |
| **Version Control** | GitHub PATs, GitLab Tokens, npm auth tokens |
| **Payment** | Stripe Secret/Webhook Keys, Square Access Tokens, Shopify |
| **Communication** | Slack Bot Tokens, Slack Webhooks, Discord, Telegram |
| **Email** | SendGrid API Keys, Mailgun API Keys, Twilio |
| **Database** | PostgreSQL, MySQL, MongoDB, Redis connection strings |
| **Cryptography** | RSA/EC/OpenSSH Private Keys, PGP Private Keys |
| **Auth** | JWT Tokens, JWT Signing Secrets, Bearer Tokens, Basic Auth in URLs |
| **Generic** | Hardcoded passwords, high-entropy strings |

**Shannon entropy analysis** catches secrets that don't match known patterns — high-randomness strings that shouldn't be in source code.

## Advantages over similar tools

| Feature | secret-scan | truffleHog | gitleaks |
|---|---|---|---|
| Zero dependencies | ✅ | ❌ | ❌ |
| Windows native | ✅ | ⚠️ | ⚠️ |
| Python (readable) | ✅ | ❌ Go | ❌ Go |
| Shannon entropy | ✅ | ✅ | ✅ |
| Git history scan | ✅ | ✅ | ✅ |
| JSON output | ✅ | ✅ | ✅ |
| Secret redaction | ✅ | ❌ | ❌ |

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
 \__ \ ) _)( (__  )   / ) _)   )( (___)\__ \( (__ /    \/    /
 (___/(____)\___)(__)\_)(____) (__)     (___/ \___)\_/\_/\_)__)

  Secrets Scanner · blind-sec

  ● CRITICAL (2)
  ──────────────────────────────────────────────────────────
  AWS Access Key ID
    Service  : AWS
    Location : src/config.py:14
    Match    : AKIA12...D3F4
    Context  : aws_access_key = "AKIA12EXAMPLE3D3F4"

  GitHub Personal Access Token (classic)
    Service  : GitHub
    Location : .env:3
    Match    : ghp_ab...ef12
    Context  : GITHUB_TOKEN=ghp_abcdef...

  ────────────────────────────────────────────────────────────
  SCAN COMPLETE
  ────────────────────────────────────────────────────────────
  Files scanned   : 147
  Lines scanned   : 12,483
  Time elapsed    : 0.31s

  Findings        : 2
  ├─ CRITICAL     : 2
  ├─ HIGH         : 0
  ├─ MEDIUM       : 0
  └─ LOW          : 0
```

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

## Architecture

```
secret_scan/
├── cli.py       — argparse CLI (scan, git, rules subcommands)
├── scanner.py   — file/directory/git scanning engine
├── rules.py     — 100+ regex detection rules with severity/service metadata
├── entropy.py   — Shannon entropy for high-randomness string detection
└── output.py    — colored terminal output + JSON formatter
```

## License

MIT — free to use, modify, and distribute.

---

*Part of [blind-sec/security-projects](https://github.com/blind-sec/security-projects)*
