#!/usr/bin/env python3
"""
Convert pip-audit JSON output to SARIF for GitHub Security tab ingestion.

Usage:
    pip-audit --requirement=requirements.txt --format=json --output=pip-audit-results.json
    python security/scripts/pip-audit-to-sarif.py
"""
import json
import sys
from pathlib import Path


INPUT_FILE = Path("pip-audit-results.json")
OUTPUT_FILE = Path("pip-audit-results.sarif")


def load_pip_audit_results(path: Path) -> dict:
    if not path.exists():
        print(f"Input file {path} not found; writing empty SARIF.", file=sys.stderr)
        return {}
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def build_sarif(data: dict) -> dict:
    rules = []
    results = []

    for dep in data.get("dependencies", []):
        name = dep.get("name", "unknown")
        version = dep.get("version", "unknown")
        vulns = dep.get("vulns", [])

        for vuln in vulns:
            vuln_id = vuln.get("id", "UNKNOWN")
            rule_id = f"pip-audit-{vuln_id}"
            if rule_id not in {r["id"] for r in rules}:
                rules.append(
                    {
                        "id": rule_id,
                        "name": vuln_id,
                        "shortDescription": {
                            "text": vuln.get("description", "No description")[:200]
                        },
                        "fullDescription": {
                            "text": vuln.get("description", "No description")
                        },
                        "defaultConfiguration": {"level": "warning"},
                        "properties": {
                            "tags": ["security", "sca", "pip-audit"],
                            "precision": "high",
                        },
                    }
                )

            fix_versions = vuln.get("fix_versions", [])
            result = {
                "ruleId": rule_id,
                "level": "warning",
                "message": {
                    "text": (
                        f"Package {name}@{version} is affected by {vuln_id}. "
                        f"Fixed versions: {', '.join(fix_versions) if fix_versions else 'unknown'}."
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": "requirements.txt",
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {"startLine": 1},
                        }
                    }
                ],
            }
            results.append(result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pip-audit",
                        "informationUri": "https://github.com/pypa/pip-audit",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def main() -> int:
    data = load_pip_audit_results(INPUT_FILE)
    sarif = build_sarif(data)
    with OUTPUT_FILE.open("w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)
    print(f"Wrote {OUTPUT_FILE} with {len(sarif['runs'][0]['results'])} results.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
