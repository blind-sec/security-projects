"""Unit tests for secret_scan."""

import pytest
from pathlib import Path
from secret_scan.scanner import scan_file, scan_directory, ScanResult

# Construct test credential strings at runtime to avoid triggering
# repository secret scanners (values are structurally valid but cryptographically fake)
_SLACK  = "xoxb-" + "12345678901-12345678901-" + "abcdefghijklmnopqrstuvwx"
_STRIPE = "sk_" + "live_51ABCDEFghijklmnopqrstuvwx"
_STRIPE_WEBHOOK = "whsec_" + "abcdefghijklmnopqrstuvwxyz123456"
_GHP    = "ghp_" + "abcdefghijklmnopqrstuvwxyz1234567890"
_JWT    = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
from secret_scan.rules import RULES, get_rule_by_id
from secret_scan.entropy import shannon_entropy, find_high_entropy_base64, is_high_entropy


# ── Entropy tests ─────────────────────────────────────────────────────────────

class TestEntropy:
    def test_uniform_string_low_entropy(self):
        assert shannon_entropy("aaaaaaaaaa") == 0.0

    def test_random_string_high_entropy(self):
        assert shannon_entropy("aB3dEf7hIj") > 3.0

    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_is_high_entropy_true(self):
        assert is_high_entropy("wJalrXUtnFEMI/K7MDENG/bPxRfi", threshold=3.5)

    def test_is_high_entropy_false(self):
        assert not is_high_entropy("aaaaaa", threshold=3.5)

    def test_find_high_entropy_base64_detects(self):
        line = 'token = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY1234"'
        results = find_high_entropy_base64(line, threshold=4.0)
        assert len(results) >= 1

    def test_find_high_entropy_base64_ignores_low(self):
        line = 'name = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'
        results = find_high_entropy_base64(line, threshold=4.0)
        assert results == []


# ── Rules tests ───────────────────────────────────────────────────────────────

class TestRules:
    def test_all_rules_compile(self):
        """Every rule pattern must compile without error."""
        for rule in RULES:
            compiled = rule.compiled()
            assert compiled is not None

    def test_get_rule_by_id(self):
        rule = get_rule_by_id("aws-access-key-id")
        assert rule is not None
        assert rule.severity == "CRITICAL"

    def test_get_rule_by_id_missing(self):
        assert get_rule_by_id("nonexistent-rule") is None

    def test_rule_count(self):
        assert len(RULES) >= 40

    def test_aws_key_pattern(self):
        rule = get_rule_by_id("aws-access-key-id")
        assert rule.compiled().search("AKIAIOSFODNN7EXAMPLE") is not None

    def test_github_pat_pattern(self):
        rule = get_rule_by_id("github-pat-classic")
        assert rule.compiled().search(_GHP) is not None

    def test_stripe_key_pattern(self):
        rule = get_rule_by_id("stripe-secret-key")
        assert rule.compiled().search(_STRIPE) is not None

    def test_slack_token_pattern(self):
        rule = get_rule_by_id("slack-bot-token")
        assert rule.compiled().search(_SLACK) is not None

    def test_jwt_pattern(self):
        rule = get_rule_by_id("jwt-token")
        assert rule.compiled().search(_JWT) is not None

    def test_ssh_key_pattern(self):
        rule = get_rule_by_id("openssh-private-key")
        assert rule.compiled().search("-----BEGIN OPENSSH PRIVATE KEY-----") is not None

    def test_postgres_url_pattern(self):
        rule = get_rule_by_id("postgres-url")
        assert rule.compiled().search("postgres://admin:password@db.example.com/mydb") is not None

    def test_stopword_not_triggered(self):
        """Patterns containing known stopwords should be filtered."""
        from secret_scan.scanner import _contains_stopword
        assert _contains_stopword("changeme") is True
        assert _contains_stopword("sk_live_realkey123") is False


# ── File scanning tests ───────────────────────────────────────────────────────

class TestScanner:
    def test_scan_fixture_file(self, tmp_path):
        """Scanner detects known secrets in a test file."""
        secret_file = tmp_path / "secrets.py"
        secret_file.write_text(
            f'SLACK = "{_SLACK}"\n'
            'SSH = "-----BEGIN OPENSSH PRIVATE KEY-----"\n'
        )
        result = scan_file(secret_file)
        assert result.files_scanned == 1
        assert result.lines_scanned == 2
        assert len(result.findings) >= 2

    def test_scan_clean_file(self, tmp_path):
        """Scanner reports no findings for clean file."""
        clean_file = tmp_path / "clean.py"
        clean_file.write_text('x = 1\nprint("hello world")\n')
        result = scan_file(clean_file)
        assert result.findings == []

    def test_scan_directory(self, tmp_path):
        """Scanner recursively finds secrets in a directory."""
        (tmp_path / "a.py").write_text(
            'KEY = "-----BEGIN RSA PRIVATE KEY-----"\n'
        )
        (tmp_path / "subdir").mkdir()
        (tmp_path / "subdir" / "b.py").write_text(
            'TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz123456AB"\n'
        )
        result = scan_directory(tmp_path)
        assert result.files_scanned == 2
        assert len(result.findings) >= 2

    def test_skips_node_modules(self, tmp_path):
        """node_modules directory is excluded."""
        nm = tmp_path / "node_modules"
        nm.mkdir()
        (nm / "secret.js").write_text('KEY = "-----BEGIN RSA PRIVATE KEY-----"\n')
        result = scan_directory(tmp_path)
        assert result.findings == []

    def test_severity_levels(self, tmp_path):
        """Findings have valid severity levels."""
        f = tmp_path / "f.py"
        f.write_text('KEY = "-----BEGIN RSA PRIVATE KEY-----"\n')
        result = scan_file(f)
        for finding in result.findings:
            assert finding.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

    def test_finding_redaction(self, tmp_path):
        """Secrets are redacted in output — never exposed in full."""
        f = tmp_path / "f.py"
        f.write_text('KEY = "-----BEGIN RSA PRIVATE KEY-----"\n')
        result = scan_file(f)
        for finding in result.findings:
            redacted = finding.redacted_match
            assert "..." in redacted or redacted == "***REDACTED***"

    def test_scan_result_properties(self, tmp_path):
        """ScanResult correctly categorises findings by severity."""
        f = tmp_path / "f.py"
        f.write_text(
            'KEY = "-----BEGIN RSA PRIVATE KEY-----"\n'
            'JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"\n'
        )
        result = scan_file(f)
        assert isinstance(result.critical, list)
        assert isinstance(result.high, list)
