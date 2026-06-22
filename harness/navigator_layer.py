"""
harness/navigator_layer.py
Generates an ATT&CK Navigator JSON layer from a set of Sigma rules.

The layer file can be imported directly into the ATT&CK Navigator at:
https://mitre-attack.github.io/attack-navigator/

Each covered technique is highlighted; the score is the number of rules
covering that technique, allowing visual density analysis.
"""

from __future__ import annotations
import json
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple
import yaml

# ATT&CK Navigator layer schema version
LAYER_VERSION = "4.5"
ATT_VERSION = "14"
NAV_VERSION = "4.9"

# Colour gradient: 1 rule = light, ≥5 rules = dark
GRADIENT_COLORS = ["#f0f0a0", "#f0a000"]   # yellow → orange


def _extract_attack_ids(tags: List[str]) -> Set[str]:
    """Extract T1234 / T1234.001 style technique IDs from tags."""
    ids: Set[str] = set()
    for tag in tags:
        if not isinstance(tag, str):
            continue
        m = re.match(r"attack.(t\d{4}(?:\.\d{3})?)", tag, re.IGNORECASE)
        if m:
            ids.add(m.group(1).upper())
    return ids


def _load_rule(path: Path) -> Tuple[str, List[str]]:
    """Return (title, list_of_attack_technique_ids) for a rule file."""
    with open(path, encoding="utf-8") as fh:
        rule = yaml.safe_load(fh)
    if not isinstance(rule, dict):
        return path.stem, []
    title = rule.get("title", path.stem)
    tags = rule.get("tags", [])
    return title, list(_extract_attack_ids(tags))


def scan_rules(rules_dir: Path) -> Dict[str, List[str]]:
    """
    Scan all rules in a directory and return a dict mapping
    technique_id → list_of_rule_titles.
    """
    coverage: Dict[str, List[str]] = {}
    for p in sorted(rules_dir.rglob("*.y*ml")):
        try:
            title, technique_ids = _load_rule(p)
            for tid in technique_ids:
                coverage.setdefault(tid, []).append(title)
        except Exception:
            continue
    return coverage


def build_layer(
    coverage: Dict[str, List[str]],
    name: str = "Sigma Rule Coverage",
    description: str = "ATT&CK technique coverage from Sigma rule pack",
) -> dict:
    """
    Build an ATT&CK Navigator JSON layer dict from coverage data.

    Parameters
    ----------
    coverage : dict
        {technique_id: [rule_title, ...]} mapping.
    name : str
        Layer name displayed in Navigator.
    description : str
        Layer description.

    Returns
    -------
    dict
        Navigator layer ready for JSON serialisation.
    """
    techniques = []
    max_count = max((len(v) for v in coverage.values()), default=1)

    for tid, rule_titles in sorted(coverage.items()):
        count = len(rule_titles)
        score = count

        # Metadata: list of covering rule titles
        metadata = [{"name": "rules", "value": " | ".join(rule_titles)}]

        # Build technique entry
        entry: dict = {
            "techniqueID": tid,
            "score": score,
            "color": "",
            "comment": f"Covered by {count} rule(s): {', '.join(rule_titles)}",
            "enabled": True,
            "metadata": metadata,
            "showSubtechniques": True,
        }
        techniques.append(entry)

    layer = {
        "name": name,
        "versions": {
            "attack": ATT_VERSION,
            "navigator": NAV_VERSION,
            "layer": LAYER_VERSION,
        },
        "domain": "enterprise-attack",
        "description": description,
        "filters": {
            "platforms": [
                "Windows", "Linux", "macOS",
                "Network", "Cloud", "Containers",
            ]
        },
        "sorting": 3,       # sort by score descending
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False,
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": GRADIENT_COLORS,
            "minValue": 0,
            "maxValue": max(max_count, 1),
        },
        "legendItems": [
            {"label": "1 rule", "color": GRADIENT_COLORS[0]},
            {"label": f"≥{max_count} rules", "color": GRADIENT_COLORS[1]},
        ],
        "metadata": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }
    return layer


def generate_layer(
    rules_dir: Path,
    output_path: Path,
    name: str = "Sigma Rule Coverage",
):
    """Convenience function: scan rules, build layer, write JSON."""
    coverage = scan_rules(rules_dir)
    layer = build_layer(coverage, name=name)

    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(layer, fh, indent=2)

    covered = len(coverage)
    total_rules = sum(len(v) for v in coverage.values())
    print(f"ATT&CK Navigator layer written to: {output_path}")
    print(f"  Techniques covered : {covered}")
    print(f"  Total rule-technique mappings : {total_rules}")
    return layer


def print_coverage_summary(coverage: Dict[str, List[str]]):
    """Print a text summary of coverage to stdout."""
    print("\n" + "=" * 50)
    print("ATT&CK TECHNIQUE COVERAGE SUMMARY")
    print("=" * 50)
    print(f"{'Technique':<15}  {'#Rules':<8}  Covering Rules")
    print("-" * 50)
    for tid, rules in sorted(coverage.items()):
        print(f"{tid:<15}  {len(rules):<8}  {', '.join(rules)}")
    print("=" * 50)
    print(f"Total: {len(coverage)} techniques covered by {sum(len(v) for v in coverage.values())} rule mappings")


if __name__ == "__main__":
    import argparse
    import sys
    parser = argparse.ArgumentParser(
        description="Generate ATT&CK Navigator layer from Sigma rules"
    )
    parser.add_argument("rules_dir", help="Directory containing Sigma rules")
    parser.add_argument(
        "--output", "-o",
        default="attack_layer.json",
        help="Output JSON file (default: attack_layer.json)"
    )
    parser.add_argument("--name", default="Sigma Rule Coverage")
    args = parser.parse_args()

    rd = Path(args.rules_dir)
    if not rd.is_dir():
        print(f"Error: '{rd}' is not a directory", file=sys.stderr)
        sys.exit(1)

    coverage = scan_rules(rd)
    print_coverage_summary(coverage)
    generate_layer(rd, Path(args.output), name=args.name)
