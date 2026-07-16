# test fixture — intentionally malformed/invalid credentials for scanner unit tests
# These are structurally valid for pattern matching but cryptographically invalid

AWS_ACCESS_KEY_ID = "AKIA" + "IOSFODNN7EXAMPLE"          # constructed, not real
AWS_SECRET        = "wJalrXUtnFEMI" + "/K7MDENG/bPxRfiCYEXAMPLEKEY"
GITHUB_TOKEN      = "ghp_" + "abcdefghijklmnopqrstuvwxyz123456AB"
STRIPE_KEY        = "sk_" + "live_51ABCDEFghijklmnopqrstuvwx"
SLACK_TOKEN       = "xoxb-" + "12345678901-12345678901-abcdefghijklmnopqrstuvwx"
DB_URL            = "postgres://admin:" + "supersecretpassword@prod-db.example.com/mydb"
JWT               = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
SSH_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----"
