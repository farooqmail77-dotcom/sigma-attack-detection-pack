"""
harness/rule_validator.py
Validates Sigma rule YAML files against schema requirements.
Checks: required fields, valid status values, ATT&CK tag format,
        UUID format, detection logic presence.
"""

from __future__ import annotations
import re
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional
import yaml

# ── Schema constants ──────────────────────────────────────────────────────────
REQUIRED_FIELDS = {"title", "id", "status", "description", "logsource", "detection"}
VALID_STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
ATTACK_TAG_RE = re.compile(r"^attack.([w.]+)$", re.IGNORECASE)
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
SEVERITY_LEVELS = {"informational", "low", "medium", "high", "critical"}


@dataclass
class ValidationResult:
    path: Path
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return len(self.errors) == 0

    def __str__(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        lines = [f"[{status}] {self.path}"]
        for e in self.errors:
            lines.append(f"  ERROR  : {e}")
        for w in self.warnings:
            lines.append(f"  WARN   : {w}")
        return "\n".join(lines)


def validate_rule(path: Path) -> ValidationResult:
    """Validate a single Sigma rule YAML file."""
    result = ValidationResult(path=path)

    # ── Parse YAML ────────────────────────────────────────────────────────────
    try:
        with open(path, encoding="utf-8") as fh:
            rule = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        result.errors.append(f"YAML parse error: {exc}")
        return result
    except Exception as exc:
        result.errors.append(f"File read error: {exc}")
        return result

    if not isinstance(rule, dict):
        result.errors.append("Rule must be a YAML mapping (dict), got: " + type(rule).__name__)
        return result

    # ── Required fields ───────────────────────────────────────────────────────
    for field_name in REQUIRED_FIELDS:
        if field_name not in rule:
            result.errors.append(f"Missing required field: '{field_name}'")

    if result.errors:
        return result  # No point continuing if required fields missing

    # ── Title ─────────────────────────────────────────────────────────────────
    title = rule.get("title", "")
    if not isinstance(title, str) or not title.strip():
        result.errors.append("'title' must be a non-empty string")
    elif len(title) > 100:
        result.warnings.append(f"'title' is long ({len(title)} chars); consider ≤ 100")

    # ── ID (UUID v4) ──────────────────────────────────────────────────────────
    rule_id = str(rule.get("id", ""))
    if not UUID_RE.match(rule_id):
        result.errors.append(f"'id' is not a valid UUID: '{rule_id}'")

    # ── Status ────────────────────────────────────────────────────────────────
    status = rule.get("status", "")
    if status not in VALID_STATUSES:
        result.errors.append(
            f"'status' must be one of {VALID_STATUSES}, got: '{status}'"
        )

    # ── Tags / ATT&CK ─────────────────────────────────────────────────────────
    tags = rule.get("tags", [])
    if not isinstance(tags, list):
        result.warnings.append("'tags' should be a list")
    else:
        attack_tags = [t for t in tags if isinstance(t, str) and t.startswith("attack.")]
        if not attack_tags:
            result.warnings.append("No ATT&CK tags found (attack.tXXXX)")
        for tag in attack_tags:
            if not ATTACK_TAG_RE.match(tag):
                result.errors.append(f"Malformed ATT&CK tag: '{tag}'")

    # ── Level ─────────────────────────────────────────────────────────────────
    level = rule.get("level", "")
    if level and level.lower() not in SEVERITY_LEVELS:
        result.errors.append(
            f"'level' must be one of {SEVERITY_LEVELS}, got: '{level}'"
        )
    elif not level:
        result.warnings.append("'level' is not set — consider adding a severity")

    # ── Detection ─────────────────────────────────────────────────────────────
    detection = rule.get("detection", {})
    if not isinstance(detection, dict):
        result.errors.append("'detection' must be a mapping")
    else:
        if "condition" not in detection:
            result.errors.append("'detection.condition' is required")
        if len(detection) < 2:
            result.warnings.append(
                "'detection' has no selection keys beyond 'condition'"
            )

    # ── Logsource ─────────────────────────────────────────────────────────────
    logsource = rule.get("logsource", {})
    if not isinstance(logsource, dict) or not logsource:
        result.errors.append("'logsource' must be a non-empty mapping")
    else:
        if "product" not in logsource and "service" not in logsource and "category" not in logsource:
            result.warnings.append(
                "'logsource' has no product/service/category — rule may not match any log source"
            )

    # ── False positives ───────────────────────────────────────────────────────
    if "falsepositives" not in rule:
        result.warnings.append("'falsepositives' field is missing")

    return result


def validate_directory(rules_dir: Path) -> List[ValidationResult]:
    """Validate all .yml/.yaml files in a directory tree."""
    results = []
    for path in sorted(rules_dir.rglob("*.y*ml")):
        results.append(validate_rule(path))
    return results


def print_report(results: List[ValidationResult]) -> int:
    """Print validation report; return exit code (0=all pass, 1=failures)."""
    passed = sum(1 for r in results if r.passed)
    failed = len(results) - passed

    print("=" * 60)
    print(f"SIGMA RULE VALIDATION REPORT")
    print(f"Total: {len(results)}  Passed: {passed}  Failed: {failed}")
    print("=" * 60)
    for result in results:
        print(result)
    print("=" * 60)
    if failed:
        print(f"\n{failed} rule(s) FAILED validation.")
        return 1
    print(f"\nAll {passed} rule(s) passed validation.")
    return 0


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Validate Sigma rule YAML files")
    parser.add_argument("path", help="Rule file or directory to validate")
    args = parser.parse_args()

    p = Path(args.path)
    if p.is_file():
        results = [validate_rule(p)]
    elif p.is_dir():
        results = validate_directory(p)
    else:
        print(f"Error: '{p}' is not a valid file or directory", file=sys.stderr)
        sys.exit(2)

    sys.exit(print_report(results))
