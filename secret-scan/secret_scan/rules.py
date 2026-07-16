"""
Detection rules for secret_scan.
Each rule defines a regex pattern, severity, and service category.
"""

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class Rule:
    id: str
    name: str
    pattern: str
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW
    service: str
    entropy_check: bool = False
    min_entropy: float = 3.5

    def compiled(self):
        return re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)


RULES: list[Rule] = [
    # ── AWS ──────────────────────────────────────────────────────────────────
    Rule("aws-access-key-id", "AWS Access Key ID",
         r"(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}",
         "CRITICAL", "AWS", entropy_check=True),
    Rule("aws-secret-access-key", "AWS Secret Access Key",
         r"(?i)aws.{0,20}['\"][0-9a-zA-Z\/+]{40}['\"]",
         "CRITICAL", "AWS", entropy_check=True, min_entropy=4.0),
    Rule("aws-mfa-seed", "AWS MFA Seed",
         r"(?i)aws_mfa_seed.{0,20}['\"][A-Z2-7]{32}['\"]",
         "HIGH", "AWS"),

    # ── GitHub ────────────────────────────────────────────────────────────────
    Rule("github-pat-classic", "GitHub Personal Access Token (classic)",
         r"ghp_[A-Za-z0-9]{36}",
         "CRITICAL", "GitHub"),
    Rule("github-pat-fine", "GitHub Fine-Grained PAT",
         r"github_pat_[A-Za-z0-9_]{82}",
         "CRITICAL", "GitHub"),
    Rule("github-oauth-token", "GitHub OAuth Token",
         r"gho_[A-Za-z0-9]{36}",
         "CRITICAL", "GitHub"),
    Rule("github-app-token", "GitHub App Token",
         r"(ghu|ghs)_[A-Za-z0-9]{36}",
         "CRITICAL", "GitHub"),

    # ── GitLab ───────────────────────────────────────────────────────────────
    Rule("gitlab-pat", "GitLab Personal Access Token",
         r"glpat-[A-Za-z0-9\-]{20}",
         "CRITICAL", "GitLab"),
    Rule("gitlab-runner", "GitLab Runner Token",
         r"glrt-[A-Za-z0-9\-]{20}",
         "HIGH", "GitLab"),

    # ── Google ───────────────────────────────────────────────────────────────
    Rule("google-api-key", "Google API Key",
         r"AIza[0-9A-Za-z\-_]{35}",
         "HIGH", "Google"),
    Rule("google-oauth-id", "Google OAuth Client ID",
         r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
         "MEDIUM", "Google"),
    Rule("google-service-account", "Google Service Account Key",
         r'"type":\s*"service_account"',
         "CRITICAL", "Google"),
    Rule("firebase-url", "Firebase Database URL",
         r"https://[a-z0-9-]+\.firebaseio\.com",
         "MEDIUM", "Google/Firebase"),
    Rule("firebase-api-key", "Firebase API Key",
         r"(?i)firebase.{0,20}['\"][A-Za-z0-9]{39}['\"]",
         "HIGH", "Google/Firebase"),

    # ── Stripe ───────────────────────────────────────────────────────────────
    Rule("stripe-secret-key", "Stripe Secret Key",
         r"sk_live_[0-9a-zA-Z]{24,}",
         "CRITICAL", "Stripe"),
    Rule("stripe-restricted-key", "Stripe Restricted Key",
         r"rk_live_[0-9a-zA-Z]{24,}",
         "CRITICAL", "Stripe"),
    Rule("stripe-publishable-key", "Stripe Publishable Key",
         r"pk_live_[0-9a-zA-Z]{24,}",
         "LOW", "Stripe"),
    Rule("stripe-webhook", "Stripe Webhook Secret",
         r"whsec_[A-Za-z0-9+/=]{32,}",
         "HIGH", "Stripe"),

    # ── Slack ────────────────────────────────────────────────────────────────
    Rule("slack-bot-token", "Slack Bot Token",
         r"xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}",
         "CRITICAL", "Slack"),
    Rule("slack-user-token", "Slack User Token",
         r"xoxp-[0-9]{11}-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{32}",
         "CRITICAL", "Slack"),
    Rule("slack-workspace-token", "Slack Workspace Token",
         r"xoxa-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}",
         "HIGH", "Slack"),
    Rule("slack-webhook", "Slack Webhook URL",
         r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
         "HIGH", "Slack"),

    # ── Twilio ───────────────────────────────────────────────────────────────
    Rule("twilio-account-sid", "Twilio Account SID",
         r"AC[a-z0-9]{32}",
         "HIGH", "Twilio"),
    Rule("twilio-auth-token", "Twilio Auth Token",
         r"(?i)twilio.{0,20}['\"][a-f0-9]{32}['\"]",
         "CRITICAL", "Twilio"),

    # ── SendGrid ──────────────────────────────────────────────────────────────
    Rule("sendgrid-api-key", "SendGrid API Key",
         r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
         "CRITICAL", "SendGrid"),

    # ── Mailgun ──────────────────────────────────────────────────────────────
    Rule("mailgun-api-key", "Mailgun API Key",
         r"key-[0-9a-zA-Z]{32}",
         "HIGH", "Mailgun"),

    # ── Heroku ───────────────────────────────────────────────────────────────
    Rule("heroku-api-key", "Heroku API Key",
         r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
         "HIGH", "Heroku", entropy_check=True),

    # ── Azure ────────────────────────────────────────────────────────────────
    Rule("azure-storage-key", "Azure Storage Account Key",
         r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
         "CRITICAL", "Azure"),
    Rule("azure-sas-token", "Azure SAS Token",
         r"(?i)sv=\d{4}-\d{2}-\d{2}&ss=",
         "HIGH", "Azure"),

    # ── GCP ──────────────────────────────────────────────────────────────────
    Rule("gcp-private-key", "GCP Private Key",
         r'"private_key":\s*"-----BEGIN RSA PRIVATE KEY-----',
         "CRITICAL", "GCP"),

    # ── Database ─────────────────────────────────────────────────────────────
    Rule("postgres-url", "PostgreSQL Connection String",
         r"postgres(?:ql)?://[^:]+:[^@]+@[^/]+/\w+",
         "CRITICAL", "Database"),
    Rule("mysql-url", "MySQL Connection String",
         r"mysql://[^:]+:[^@]+@[^/]+/\w+",
         "CRITICAL", "Database"),
    Rule("mongodb-url", "MongoDB Connection String",
         r"mongodb(?:\+srv)?://[^:]+:[^@]+@",
         "CRITICAL", "Database"),
    Rule("redis-url", "Redis Connection String",
         r"redis://:[^@]+@",
         "HIGH", "Database"),

    # ── Private Keys ──────────────────────────────────────────────────────────
    Rule("rsa-private-key", "RSA Private Key",
         r"-----BEGIN RSA PRIVATE KEY-----",
         "CRITICAL", "Cryptography"),
    Rule("ec-private-key", "EC Private Key",
         r"-----BEGIN EC PRIVATE KEY-----",
         "CRITICAL", "Cryptography"),
    Rule("openssh-private-key", "OpenSSH Private Key",
         r"-----BEGIN OPENSSH PRIVATE KEY-----",
         "CRITICAL", "Cryptography"),
    Rule("pgp-private-key", "PGP Private Key",
         r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
         "CRITICAL", "Cryptography"),

    # ── JWT ──────────────────────────────────────────────────────────────────
    Rule("jwt-token", "JWT Token",
         r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
         "HIGH", "Auth"),
    Rule("jwt-secret", "JWT Secret/Signing Key",
         r"(?i)jwt.{0,20}secret.{0,5}['\"][^'\"]{8,}['\"]",
         "CRITICAL", "Auth"),

    # ── Generic Passwords ────────────────────────────────────────────────────
    Rule("hardcoded-password", "Hardcoded Password",
         r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]",
         "HIGH", "Generic", entropy_check=True, min_entropy=2.5),
    Rule("hardcoded-secret", "Hardcoded Secret",
         r"(?i)(?:secret|token|api_key|apikey|auth_token)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
         "HIGH", "Generic", entropy_check=True),

    # ── URL with credentials ──────────────────────────────────────────────────
    Rule("url-with-creds", "URL with Embedded Credentials",
         r"https?://[^:]+:[^@]{3,}@[^\s/\"']+",
         "HIGH", "Generic"),

    # ── Bearer Token ─────────────────────────────────────────────────────────
    Rule("bearer-token", "Bearer Token in Header",
         r"(?i)Authorization:\s*Bearer\s+[A-Za-z0-9_\-\.]+",
         "HIGH", "Auth"),

    # ── Npm / Yarn ───────────────────────────────────────────────────────────
    Rule("npm-auth-token", "npm Auth Token",
         r"(?i)//registry\.npmjs\.org/:_authToken=[A-Za-z0-9\-_]+",
         "HIGH", "npm"),

    # ── Shopify ──────────────────────────────────────────────────────────────
    Rule("shopify-shared-secret", "Shopify Shared Secret",
         r"shpss_[A-Fa-f0-9]{32}",
         "CRITICAL", "Shopify"),
    Rule("shopify-access-token", "Shopify Access Token",
         r"shpat_[A-Fa-f0-9]{32}",
         "CRITICAL", "Shopify"),

    # ── Telegram ─────────────────────────────────────────────────────────────
    Rule("telegram-bot-token", "Telegram Bot Token",
         r"\d{9,10}:[A-Za-z0-9_\-]{35}",
         "HIGH", "Telegram"),

    # ── Discord ──────────────────────────────────────────────────────────────
    Rule("discord-bot-token", "Discord Bot Token",
         r"(?i)discord.{0,20}['\"][A-Za-z0-9\.\-_]{59}['\"]",
         "HIGH", "Discord"),
    Rule("discord-webhook", "Discord Webhook URL",
         r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+",
         "HIGH", "Discord"),

    # ── Coinbase ─────────────────────────────────────────────────────────────
    Rule("coinbase-api-key", "Coinbase API Key",
         r"(?i)coinbase.{0,20}['\"][a-zA-Z0-9]{32,}['\"]",
         "CRITICAL", "Coinbase"),

    # ── Square ───────────────────────────────────────────────────────────────
    Rule("square-access-token", "Square Access Token",
         r"sq0atp-[A-Za-z0-9\-_]{22}",
         "CRITICAL", "Square"),
    Rule("square-oauth-secret", "Square OAuth Secret",
         r"sq0csp-[A-Za-z0-9\-_]{43}",
         "CRITICAL", "Square"),
]


ALLOWLISTED_PATHS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "vendor", "dist", "build", ".next", "coverage",
}

STOPWORDS = {
    "example", "sample", "placeholder", "your-", "your_", "xxx",
    "changeme", "replace", "insert", "<", ">", "...", "test",
    "dummy", "fake", "mock", "demo",
}


def get_rule_by_id(rule_id: str) -> Optional[Rule]:
    for rule in RULES:
        if rule.id == rule_id:
            return rule
    return None
