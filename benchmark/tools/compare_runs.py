"""Aggregate independent scored runs without hiding gate failures."""
from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path
import statistics

from common import read_json, write_json


def numeric_median(values):
    values = [value for value in values if isinstance(value, (int, float)) and not isinstance(value, bool)]
    return statistics.median(values) if values else None


def aggregate(scores):
    groups = defaultdict(list)
    for value in scores:
        metrics = value.get("metrics", {})
        model = metrics.get("model_id")
        run_id = metrics.get("run_id")
        if not isinstance(model, str) or not model or not isinstance(run_id, str) or not run_id:
            raise ValueError("Every score needs metrics.model_id and metrics.run_id")
        groups[model].append(value)
    models = []
    for model, runs in sorted(groups.items()):
        clean = [not run["failed_gates"] for run in runs]
        models.append({
            "model_id": model,
            "run_count": len(runs),
            "median_score": numeric_median([run["final_score"] for run in runs]),
            "score_range": [min(run["final_score"] for run in runs), max(run["final_score"] for run in runs)],
            "all_gates_pass_rate": sum(clean) / len(clean),
            "pass_at_1": clean[0],
            "pass_at_3": any(clean[:3]),
            "median_wall_clock_seconds": numeric_median([run["metrics"].get("wall_clock_seconds") for run in runs]),
            "median_tokens": numeric_median([run["metrics"].get("tokens") for run in runs]),
            "median_cost": numeric_median([run["metrics"].get("cost") for run in runs]),
            "runs": [run["metrics"]["run_id"] for run in runs],
        })
    return {"schema_version": 1, "models": models}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scores", nargs="+", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = aggregate([read_json(path) for path in args.scores])
    write_json(args.output, result)
    for model in result["models"]:
        print(model["model_id"], "median=", model["median_score"], "pass@3=", model["pass_at_3"])


if __name__ == "__main__":
    main()
