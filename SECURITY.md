# Security Scanning Guide

This repository uses a **Snyk-primary, open-source-backup** security strategy.

- **Snyk** is already integrated with the repo via its GitHub app. It provides the primary coverage for SAST, SCA, container and IaC.
- **Open-source tools** run in GitHub Actions as backups. They guarantee that scans remain reproducible locally, avoid SaaS rate limits, and give you hands-on experience with each tool.

All CI jobs are configured to run in **non-blocking** mode so you can review findings, build a baseline, and decide which vulnerabilities to fix.

## Tool mapping

| Domain | Primary | Backup | Config (backup) | Output |
|---|---|---|---|---|
| Secrets | Gitleaks | — | `security/gitleaks/gitleaks.toml` | Logs + CI exit code |
| SAST | Snyk Code | Semgrep | `security/semgrep/semgrep-config.yml` | SARIF |
| SCA | Snyk Open Source | pip-audit | — | SARIF (via `security/scripts/pip-audit-to-sarif.py`) |
| Dockerfile lint | Snyk Container | Hadolint | `security/hadolint.yml` | SARIF |
| Image OS/libs | Snyk Container | Trivy image | `security/trivy/.trivyignore` | SARIF |
| IaC/config | Snyk IaC | Checkov | `security/checkov-config.yml` | SARIF |
| DAST (future) | OWASP ZAP | — | `security/zap/zap-baseline.conf` | SARIF |
| Policy/ignores | Snyk UI / `.snyk` | `security/snyk-policy.yml` | — | — |

## Running locally

### Secrets

```bash
docker run --rm -v "$PWD:/path" zricethezav/gitleaks detect \
  --source /path \
  --config /path/security/gitleaks/gitleaks.toml
```

### SAST

```bash
# Semgrep (backup)
pip install semgrep
semgrep --config=security/semgrep/semgrep-config.yml \
        --config=p/python \
        --config=p/owasp-top-ten \
        --config=p/cwe-top-25
```

### SCA

```bash
# pip-audit (backup)
pip install pip-audit
pip-audit --requirement=requirements.txt --desc
```

### Container

```bash
# Hadolint (backup)
docker run --rm -i hadolint/hadolint < Dockerfile

# Build + Trivy image (backup)
docker build -t vuln-bank:local .
trivy image vuln-bank:local --trivyignore security/trivy/.trivyignore
```

### IaC/config

```bash
# Checkov (backup)
pip install checkov
checkov --file Dockerfile --file docker-compose.yml \
        --config-file security/checkov-config.yml --soft-fail
```

## Quality gates

The current pipeline uses `continue-on-error: true` / `--exit-zero` / `--soft-fail` / `|| true` everywhere. To harden the gate later:

1. Review findings in the GitHub **Security** tab and in the Snyk dashboard.
2. Add accepted/intentional findings to the relevant baseline file:
   - Semgrep: `# nosem` comment or update `security/semgrep/semgrep-config.yml`.
   - pip-audit: add CVEs with reasons to `.trivyignore` or update `requirements.txt`.
   - Trivy image: add CVEs with reasons to `security/trivy/.trivyignore`.
   - Checkov: add check IDs to `skip-check` in `security/checkov-config.yml`.
   - Gitleaks: add regexes/paths to `security/gitleaks/gitleaks.toml`.
   - Snyk: use the Snyk UI or add ignores to `.snyk` / `security/snyk-policy.yml`.
3. Remove `continue-on-error: true` from the jobs you want to make blocking.
4. Update the `security-summary` job to enforce thresholds (for example, fail on new CRITICAL/HIGH findings).

## DAST placeholder

OWASP ZAP is not enabled yet. When you are ready, add a job that:

1. Starts the stack with `docker compose up -d`.
2. Runs `zaproxy/action-baseline@v0.14.0` (or the latest version) against `http://127.0.0.1:5000`.
3. Uses `security/zap/zap-baseline.conf` for exclusions.
4. Uploads the generated SARIF.

## Important note

This application contains intentional vulnerabilities for educational purposes. Never deploy the main branch to a production environment without first reviewing and mitigating findings.
