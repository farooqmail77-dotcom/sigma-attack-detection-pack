#!/usr/bin/env python3
"""
run_harness.py
Master CLI for the Sigma ATT&CK detection harness.

Commands
--------
  validate      Lint all Sigma rules and report errors
  convert       Convert rules to Splunk SPL
  layer         Generate ATT&CK Navigator coverage layer
  all           Run all three (default)

Usage
-----
  python run_harness.py validate [--rules-dir RULES_DIR]
  python run_harness.py convert  [--rules-dir RULES_DIR] [--output FILE]
  python run_harness.py layer    [--rules-dir RULES_DIR] [--output FILE]
  python run_harness.py all      [--rules-dir RULES_DIR] [--out-dir DIR]
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from harness.rule_validator import validate_directory, print_report
from harness.splunk_converter import convert_directory, print_spl_report
from harness.navigator_layer import scan_rules, build_layer, generate_layer, print_coverage_summary
import json


DEFAULT_RULES_DIR = Path(__file__).parent


def cmd_validate(args) -> int:
    rules_dir = Path(args.rules_dir)
    print(f"\nValidating Sigma rules in: {rules_dir.resolve()}\n")
    results = validate_directory(rules_dir)
    if not results:
        print("No rule files found.")
        return 0
    return print_report(results)


def cmd_convert(args) -> int:
    rules_dir = Path(args.rules_dir)
    print(f"\nConverting Sigma rules to Splunk SPL: {rules_dir.resolve()}\n")
    results = convert_directory(rules_dir)
    if not results:
        print("No rule files found.")
        return 0
    if args.output:
        out = Path(args.output)
        with open(out, "w", encoding="utf-8") as fh:
            for _, title, spl in results:
                fh.write(f"## {title}\n{spl}\n\n")
        print(f"Saved {len(results)} SPL queries to {out}")
    else:
        print_spl_report(results)
    return 0


def cmd_layer(args) -> int:
    rules_dir = Path(args.rules_dir)
    out = Path(args.output) if args.output else Path("attack_layer.json")
    print(f"\nGenerating ATT&CK Navigator layer from: {rules_dir.resolve()}")
    coverage = scan_rules(rules_dir)
    if not coverage:
        print("No ATT&CK-tagged rules found.")
        return 0
    print_coverage_summary(coverage)
    generate_layer(rules_dir, out, name="Sigma Rule Coverage")
    return 0


def cmd_all(args) -> int:
    rules_dir = Path(args.rules_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("SIGMA HARNESS — RUNNING ALL CHECKS")
    print("=" * 60)

    # 1. Validate
    print("\n[1/3] VALIDATION")
    args.rules_dir = str(rules_dir)
    rc_validate = cmd_validate(args)

    # 2. Convert
    print("\n[2/3] SPL CONVERSION")
    args.output = str(out_dir / "splunk_queries.spl")
    rc_convert = cmd_convert(args)

    # 3. Navigator layer
    print("\n[3/3] ATT&CK NAVIGATOR LAYER")
    args.output = str(out_dir / "attack_layer.json")
    rc_layer = cmd_layer(args)

    print("\n" + "=" * 60)
    print(f"Done. Reports written to: {out_dir.resolve()}")
    print("=" * 60)

    return max(rc_validate, rc_convert, rc_layer)


def main():
    parser = argparse.ArgumentParser(
        description="Sigma ATT&CK Detection Harness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=["validate", "convert", "layer", "all"],
        default="all",
    )
    parser.add_argument(
        "--rules-dir",
        default=str(DEFAULT_RULES_DIR),
        help=f"Directory containing Sigma rule YAML files (default: {DEFAULT_RULES_DIR})"
    )
    parser.add_argument("--output", "-o", help="Output file path")
    parser.add_argument(
        "--out-dir",
        default="reports",
        help="Output directory for 'all' command (default: reports/)"
    )
    args = parser.parse_args()

    commands = {
        "validate": cmd_validate,
        "convert":  cmd_convert,
        "layer":    cmd_layer,
        "all":      cmd_all,
    }
    sys.exit(commands[args.command](args))


if __name__ == "__main__":
    main()
