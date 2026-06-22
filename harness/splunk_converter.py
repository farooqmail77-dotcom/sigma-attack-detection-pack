"""
harness/splunk_converter.py
Converts Sigma detection logic to Splunk SPL (Search Processing Language).

This is a simplified converter that handles the most common Sigma patterns:
- Field equality / contains / endswith / startswith / regex matching
- AND / OR logic between multiple fields
- count() aggregation for timeframe-based rules
- Condition expressions (selection, NOT, AND, OR between selections)

For full Sigma-to-SPL conversion, use the official sigma-cli tool:
    https://github.com/SigmaHQ/sigma-cli

This module demonstrates the conversion logic for portfolio purposes.
"""

from __future__ import annotations
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import yaml


# ── SPL operator mapping ─────────────────────────────────────────────────────
MODIFIER_MAP = {
    "contains":     lambda f, v: f'{f}="*{v}*"',
    "startswith":   lambda f, v: f'{f}="{v}*"',
    "endswith":     lambda f, v: f'{f}="*{v}"',
    "re":           lambda f, v: f'{f}=~"{v}"',
    "all":          None,   # handled specially
    "base64":       None,   # not supported in simple converter
}


def _quote(value: Any) -> str:
    """Quote a value for SPL."""
    s = str(value)
    if " " in s or "*" in s or s == "":
        return f'"{s}"'
    return s


def _field_to_spl(field: str, value: Any) -> str:
    """
    Convert a single Sigma field match to SPL.
    Handles modifiers (field|modifier: value).
    """
    parts = field.split("|")
    base_field = parts[0]
    modifier = parts[1].lower() if len(parts) > 1 else None

    if isinstance(value, list):
        sub_exprs = []
        for v in value:
            if modifier and modifier in MODIFIER_MAP and MODIFIER_MAP[modifier]:
                sub_exprs.append(MODIFIER_MAP[modifier](base_field, v))
            else:
                sub_exprs.append(f'{base_field}={_quote(v)}')
        return "(" + " OR ".join(sub_exprs) + ")"
    else:
        if modifier and modifier in MODIFIER_MAP and MODIFIER_MAP[modifier]:
            return MODIFIER_MAP[modifier](base_field, str(value))
        return f'{base_field}={_quote(value)}'


def _selection_to_spl(selection: Dict[str, Any]) -> str:
    """Convert a detection selection dict to an SPL expression."""
    clauses = []
    for field, value in selection.items():
        if field == "EventID" and isinstance(value, list):
            # Common pattern: EventID in list
            ids = " OR ".join(f"EventID={v}" for v in value)
            clauses.append(f"({ids})")
        else:
            clauses.append(_field_to_spl(field, value))
    return " AND ".join(clauses)


def _parse_condition(condition: str, selections: Dict[str, Any]) -> str:
    """
    Parse a Sigma condition expression and return SPL.
    Handles: selection, NOT, AND, OR, count() | timeframe > N, named groups.
    """
    # Aggregation: "selection | count() by X > N" → stats search
    agg_match = re.match(
        r"(\w+)\s*\|\s*count\(\)\s*by\s*(\w+)\s*>\s*(\d+)", condition
    )
    if agg_match:
        sel_name, group_by, threshold = agg_match.groups()
        sel_spl = _selection_to_spl(selections.get(sel_name, {}))
        return (
            f"({sel_spl}) | stats count by {group_by} | where count > {threshold}"
        )

    # Simple condition parsing
    expr = condition.strip()

    # Replace selection names with their SPL
    for name in sorted(selections.keys(), key=len, reverse=True):
        if name in expr:
            sel_spl = f"({_selection_to_spl(selections[name])})"
            expr = expr.replace(name, sel_spl)

    # Replace operators
    expr = re.sub(r"\bnot\b", "NOT", expr, flags=re.IGNORECASE)
    expr = re.sub(r"\band\b", "AND", expr, flags=re.IGNORECASE)
    expr = re.sub(r"\bor\b", "OR", expr, flags=re.IGNORECASE)
    return expr


def sigma_to_spl(rule: Dict[str, Any]) -> str:
    """
    Convert a parsed Sigma rule dict to a Splunk SPL query.

    Returns the SPL string.
    """
    detection = rule.get("detection", {})
    condition = detection.get("condition", "")
    logsource = rule.get("logsource", {})

    # Extract named selections (everything except 'condition', 'timeframe', 'filter_*')
    selections = {
        k: v
        for k, v in detection.items()
        if k not in {"condition", "timeframe"} and isinstance(v, dict)
    }
    filter_keys = {k: v for k, v in selections.items() if k.startswith("filter")}
    select_keys = {k: v for k, v in selections.items() if not k.startswith("filter")}

    # Build source specification
    spl_parts = []
    index = "index=* "
    if logsource.get("product") == "windows":
        if logsource.get("service") == "security":
            index = 'index=wineventlog source="WinEventLog:Security" '
        elif logsource.get("service") == "system":
            index = 'index=wineventlog source="WinEventLog:System" '
        elif logsource.get("category") == "process_creation":
            index = 'index=wineventlog EventCode=4688 '

    # Build the main search
    condition_spl = _parse_condition(condition, selections)
    spl_query = f"{index}| search {condition_spl}"

    # Add NOT filter if present
    for fk, fv in filter_keys.items():
        filter_spl = _selection_to_spl(fv)
        spl_query += f" AND NOT ({filter_spl})"

    # Add fields projection
    fields = rule.get("fields", [])
    if fields:
        spl_query += " | table " + ", ".join(fields)

    return spl_query.strip()


def convert_rule_file(path: Path) -> Tuple[str, str]:
    """Load a Sigma rule file and return (rule_title, spl_query)."""
    with open(path, encoding="utf-8") as fh:
        rule = yaml.safe_load(fh)
    title = rule.get("title", path.stem)
    spl = sigma_to_spl(rule)
    return title, spl


def convert_directory(rules_dir: Path) -> List[Tuple[Path, str, str]]:
    """Convert all rules in a directory. Returns list of (path, title, spl)."""
    results = []
    for path in sorted(rules_dir.rglob("*.y*ml")):
        try:
            title, spl = convert_rule_file(path)
            results.append((path, title, spl))
        except Exception as exc:
            results.append((path, str(path.stem), f"-- CONVERSION ERROR: {exc}"))
    return results


def print_spl_report(results: List[Tuple[Path, str, str]]):
    """Print all converted SPL queries to stdout."""
    print("=" * 70)
    print("SIGMA → SPLUNK SPL CONVERSION REPORT")
    print("=" * 70)
    for path, title, spl in results:
        print(f"\n## {title}")
        print(f"# Source: {path}")
        print(spl)
        print()
    print(f"Converted {len(results)} rules.")


if __name__ == "__main__":
    import argparse
    import sys
    parser = argparse.ArgumentParser(description="Convert Sigma rules to Splunk SPL")
    parser.add_argument("path", help="Rule file or directory")
    parser.add_argument("--output", "-o", help="Write output to file")
    args = parser.parse_args()

    p = Path(args.path)
    if p.is_file():
        title, spl = convert_rule_file(p)
        results = [(p, title, spl)]
    elif p.is_dir():
        results = convert_directory(p)
    else:
        print(f"Error: '{p}' not found", file=sys.stderr)
        sys.exit(1)

    if args.output:
        with open(args.output, "w") as fh:
            for _, title, spl in results:
                fh.write(f"## {title}\n{spl}\n\n")
        print(f"Saved {len(results)} SPL queries to {args.output}")
    else:
        print_spl_report(results)
