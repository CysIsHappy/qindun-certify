#!/usr/bin/env python3
"""Run QinDun's deterministic corpus or public benchmarks through ClawScan."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import qindun_certify as engine  # noqa: E402 - 与统一入口共同发布


PUBLIC_BENCHMARKS = {"SkillTrustBench", "clawhub-security-signals"}


def corpus_report() -> dict:
    corpus = json.loads(engine.RULE_CORPUS_FILE.read_text(encoding="utf-8"))
    true_positive = false_negative = true_negative = false_positive = 0
    per_rule: list[dict] = []
    for case in corpus["cases"]:
        rule = engine.RULES_BY_ID[case["rule_id"]]
        positive_hits = sum(rule.pattern.search(value) is not None for value in case["positive"])
        negative_hits = sum(rule.pattern.search(value) is not None for value in case["negative"])
        true_positive += positive_hits
        false_negative += len(case["positive"]) - positive_hits
        false_positive += negative_hits
        true_negative += len(case["negative"]) - negative_hits
        per_rule.append(
            {
                "rule_id": case["rule_id"],
                "positive_total": len(case["positive"]),
                "positive_hits": positive_hits,
                "negative_total": len(case["negative"]),
                "negative_hits": negative_hits,
                "passed": positive_hits == len(case["positive"]) and negative_hits == 0,
            }
        )
    total = true_positive + false_negative + true_negative + false_positive
    precision_denominator = true_positive + false_positive
    recall_denominator = true_positive + false_negative
    precision = true_positive / precision_denominator if precision_denominator else 0.0
    recall = true_positive / recall_denominator if recall_denominator else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "format": "qindun-benchmark/v1",
        "benchmark": "qindun-rule-corpus",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scanner_version": engine.SCANNER_VERSION,
        "rule_bundle_version": engine.RULE_BUNDLE_VERSION,
        "rule_bundle_digest": engine.RULE_BUNDLE_DIGEST,
        "corpus_digest": "sha256:" + engine.RULE_CORPUS_DIGEST,
        "metrics": {
            "true_positive": true_positive,
            "false_negative": false_negative,
            "true_negative": true_negative,
            "false_positive": false_positive,
            "accuracy": (true_positive + true_negative) / total if total else 0.0,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "passed_rules": sum(item["passed"] for item in per_rule),
            "total_rules": len(per_rule),
        },
        "cases": per_rule,
    }


def clawscan_config(qindun_script: Path) -> str:
    command = (
        f"{shlex.quote(sys.executable)} {shlex.quote(str(qindun_script.resolve()))} "
        "clawscan-adapter {{target}}"
    )
    return f"""version: 1
profiles:
  qindun:
    scanners:
      - id: qindun
        command: >
          {command}
        targets:
          - skill
          - plugin
        gate:
          rules:
            - id: qindun-grade-c
              path: local_grade_preview
              equals: C
              action: warn
            - id: qindun-grade-d
              path: local_grade_preview
              equals: D
              action: warn
            - id: qindun-partial
              path: scan_status
              equals: partial
              action: warn
            - id: qindun-external-partial
              path: external_scanners.status
              equals: partial
              action: warn
"""


def public_command(
    benchmark: str,
    *,
    config: Path,
    output: Path,
    limit: int | None,
    offset: int | None,
    split: str | None,
) -> list[str]:
    command = [
        "clawscan",
        "benchmark",
        benchmark,
        "--config",
        str(config),
        "--profile",
        "qindun",
        "--sandbox",
        "off",
        "--output",
        str(output),
    ]
    if limit is not None:
        command.extend(["--limit", str(limit)])
    if offset is not None:
        command.extend(["--offset", str(offset)])
    if split:
        command.extend(["--split", split])
    return command


def _write_json(path: Path | None, document: dict) -> None:
    rendered = json.dumps(document, ensure_ascii=False, indent=2) + "\n"
    if path is None:
        sys.stdout.write(rendered)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(rendered, encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="运行秦盾规则语料，或通过 ClawScan 运行公开安全基准"
    )
    parser.add_argument(
        "benchmark",
        choices=("corpus", "SkillTrustBench", "clawhub-security-signals"),
    )
    parser.add_argument("--output", type=Path, help="保存 JSON 基准结果")
    parser.add_argument("--limit", type=int, help="公开基准最多运行的样本数")
    parser.add_argument("--offset", type=int, help="公开基准起始偏移")
    parser.add_argument("--split", help="公开基准数据分组")
    args = parser.parse_args(argv)
    if args.benchmark == "corpus":
        if args.limit is not None or args.offset is not None or args.split is not None:
            parser.error("内置规则语料不接受 --limit、--offset 或 --split")
        report = corpus_report()
        _write_json(args.output, report)
        return 0 if report["metrics"]["passed_rules"] == report["metrics"]["total_rules"] else 1
    if args.output is None:
        parser.error("公开基准必须提供 --output")
    if args.limit is not None and args.limit < 1:
        parser.error("--limit 必须大于 0")
    if args.offset is not None and args.offset < 0:
        parser.error("--offset 不能小于 0")
    if shutil.which("clawscan") is None:
        sys.stderr.write("秦盾基准失败：没有找到 clawscan 命令\n")
        return engine.EXIT_SCAN_ERROR
    with tempfile.TemporaryDirectory(prefix="qindun-clawscan-config-") as directory:
        config = Path(directory) / "clawscan.yml"
        config.write_text(clawscan_config(SCRIPT_DIR / "qindun.py"), encoding="utf-8")
        command = public_command(
            args.benchmark,
            config=config,
            output=args.output.resolve(),
            limit=args.limit,
            offset=args.offset,
            split=args.split,
        )
        try:
            completed = subprocess.run(command, shell=False, check=False)
        except OSError as error:
            sys.stderr.write(f"秦盾基准失败：{error}\n")
            return engine.EXIT_SCAN_ERROR
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
