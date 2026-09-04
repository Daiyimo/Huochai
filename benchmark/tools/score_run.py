"""Apply the fixed rubric and failed-gate cap to an assessment."""
from __future__ import annotations

import argparse
from pathlib import Path

from common import BENCHMARK, read_json, write_json


def passed(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, dict) and isinstance(value.get("passed"), bool):
        if not isinstance(value.get("evidence"), list) or not value["evidence"]:
            raise ValueError("Gate evidence must be a non-empty list")
        return value["passed"]
    raise ValueError("Gate values must be booleans or {passed,evidence} objects")


def earned(value):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    if isinstance(value, dict) and isinstance(value.get("earned"), (int, float)):
        if not isinstance(value.get("evidence"), list) or not value["evidence"]:
            raise ValueError("Dimension evidence must be a non-empty list")
        return value["earned"]
    raise ValueError("Dimension values must be numbers or {earned,evidence} objects")


def score(assessment, rubric):
    if assessment.get("schema_version") != 1:
        raise ValueError("Unsupported assessment schema")
    expected_gates = {item["id"] for item in rubric["gates"]}
    expected_dimensions = {item["id"] for item in rubric["dimensions"]}
    if set(assessment.get("gates", {})) != expected_gates:
        raise ValueError("Assessment gates do not match the rubric")
    if set(assessment.get("dimensions", {})) != expected_dimensions:
        raise ValueError("Assessment dimensions do not match the rubric")
    gate_results = {key: passed(value) for key, value in assessment["gates"].items()}
    points = {}
    for item in rubric["dimensions"]:
        value = earned(assessment["dimensions"][item["id"]])
        if value < 0 or value > item["points"]:
            raise ValueError("Dimension score outside range: " + item["id"])
        points[item["id"]] = value
    raw = sum(points.values())
    failed = sorted(key for key, value in gate_results.items() if not value)
    final = min(raw, rubric["failed_gate_score_cap"]) if failed else raw
    return {
        "schema_version": 1,
        "task_id": assessment["task_id"],
        "raw_score": raw,
        "final_score": final,
        "maximum_score": rubric["total_points"],
        "failed_gates": failed,
        "gate_cap_applied": bool(failed and raw > rubric["failed_gate_score_cap"]),
        "dimensions": points,
        "metrics": assessment.get("metrics", {}),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assessment", type=Path, required=True)
    parser.add_argument("--rubric", type=Path, default=BENCHMARK / "rubric.json")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = score(read_json(args.assessment), read_json(args.rubric))
    write_json(args.output, result)
    print("Benchmark score:", result["final_score"], "/", result["maximum_score"])


if __name__ == "__main__":
    main()
