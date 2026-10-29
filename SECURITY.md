# Security Policy

This project is infrastructure that other applications are built on. Please
treat any discovered flaw as sensitive and follow the reporting process below.

## Supported Versions

The project is pre-1.0 (`0.1.x`). Security fixes land on the **current release
line**; we do not maintain parallel branches unless stated.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

Use the version reported by the server itself:

```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" http://127.0.0.1:8081/admin/v1/version
```

## Reporting a Vulnerability

**Do not open a public issue.** Report privately.

Preferred channels:

- **GitHub private vulnerability reporting** — Security → *Report a
  vulnerability* (recommended).
- **Email** to `security@files.scc.edu.hk` — the production server publishes
  contact details and any PGP key at `/.well-known/security.txt`.

Please include:

- The affected version (from the endpoint above or `Cargo.toml`).
- A minimal, self-contained reproduction (no credentials/keys in it).
- The impact: what an attacker can actually do, and any suggested fix.

What happens next:

| Step | Expectation |
|------|-------------|
| Acknowledgement | Within **3 business days** |
| Status updates | At least every **7 days** until resolved |
| Accepted | Fixed in the current release; coordinated disclosure; credit on request |
| Declined / not reproducible | We explain why and close the report |

Please observe a **90-day coordinated disclosure window** before publishing.
For issues that are already public, we triage them in the same 3-day window.

If you find a misconfiguration or documentation error rather than a code
vulnerability, open a normal issue instead — it is not covered by this policy.
