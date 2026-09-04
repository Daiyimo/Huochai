from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest


TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))

from common import BENCHMARK, checked_relative, read_json
from compare_runs import aggregate
from fixture_generator import source_for
from generate_corpus import generate
from normalize_input import normalize
from prepare_starter import prepare
from score_run import score
from validate_submission import validate
from validate_starter import validate as validate_starter


class BenchmarkToolTests(unittest.TestCase):
    def test_rubric_is_exactly_one_hundred_points(self):
        rubric = read_json(BENCHMARK / "rubric.json")
        self.assertEqual(sum(item["points"] for item in rubric["dimensions"]), 100)
        self.assertEqual(len({item["id"] for item in rubric["dimensions"]}), len(rubric["dimensions"]))
        self.assertEqual(len({item["id"] for item in rubric["gates"]}), len(rubric["gates"]))

    def assessment(self, gate=True, points=True):
        rubric = read_json(BENCHMARK / "rubric.json")
        return {
            "schema_version": 1,
            "task_id": "fixture",
            "gates": {item["id"]: {"passed": gate, "evidence": ["test"]} for item in rubric["gates"]},
            "dimensions": {
                item["id"]: {"earned": item["points"] if points else 0, "evidence": ["test"]}
                for item in rubric["dimensions"]
            },
            "metrics": {"model_id": "model-a", "run_id": "run-1"},
        }

    def test_gate_failure_caps_an_otherwise_perfect_score(self):
        rubric = read_json(BENCHMARK / "rubric.json")
        assessment = self.assessment()
        assessment["gates"][rubric["gates"][0]["id"]]["passed"] = False
        result = score(assessment, rubric)
        self.assertEqual(result["raw_score"], 100)
        self.assertEqual(result["final_score"], 59)
        self.assertTrue(result["gate_cap_applied"])

    def test_clean_perfect_score_is_not_capped(self):
        result = score(self.assessment(), read_json(BENCHMARK / "rubric.json"))
        self.assertEqual(result["final_score"], 100)
        self.assertFalse(result["failed_gates"])

    def test_corpus_is_reproducible_and_seed_changes_content(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = generate(root / "a", 41, 30)
            second = generate(root / "b", 41, 30)
            third = generate(root / "c", 42, 30)
            self.assertEqual(first, second)
            self.assertNotEqual(first["files"], third["files"])

    def test_manifest_paths_reject_traversal_and_backslashes(self):
        self.assertEqual(checked_relative("base/input.exe"), Path("base/input.exe"))
        for value in ("../input.exe", "/input.exe", "base\\input.exe"):
            with self.assertRaises(ValueError):
                checked_relative(value)

    def test_private_input_failure_leaves_no_starter(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "starter"
            with self.assertRaises(FileNotFoundError):
                prepare("t2", output, None, root / "missing", None)
            self.assertFalse(output.exists())

    def test_starter_validation_detects_input_changes_and_answer_material(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);starter=root/'starter';(starter/'inputs').mkdir(parents=True)
            source=starter/'inputs/original.exe';source.write_bytes(b'fixture')
            digest=__import__('hashlib').sha256(source.read_bytes()).hexdigest()
            lock={"task_id":"task","files":[{"path":"inputs/original.exe","size":7,"sha256":digest}]}
            (starter/'.input-lock.json').write_text(json.dumps(lock),encoding='utf-8')
            self.assertTrue(validate_starter(starter)['valid'])
            source.write_bytes(b'changed')
            with self.assertRaises(ValueError):validate_starter(starter)
            source.write_bytes(b'fixture');(starter/'reverse').mkdir()
            with self.assertRaises(ValueError):validate_starter(starter)

    def test_normalizer_rejects_hash_before_creating_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.exe"
            source.write_bytes(b"fixture")
            output = root / "normalized"
            with self.assertRaises(ValueError):
                normalize(source, "0" * 64, output, root / "missing-7z.exe", 10, 100)
            self.assertFalse(output.exists())

    def test_submission_contract_requires_all_requirement_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = {
                "id": "task", "requirements": [{"id": "R1", "description": "x"}],
                "submission": {"required_files": ["source", "report.json", "decisions.md"]},
            }
            (root / "task.json").write_text(json.dumps(task), encoding="utf-8")
            submission = root / "submission"
            (submission / "source").mkdir(parents=True)
            (submission / "source/code.c").write_text("int main(void){return 0;}")
            (submission / "decisions.md").write_text("evidence")
            report = {
                "schema_version": 1, "task_id": "task", "known_limitations": [],
                "requirements": [{"id": "R1", "implementation": "code.c", "evidence": ["test"]}],
            }
            (submission / "report.json").write_text(json.dumps(report), encoding="utf-8")
            self.assertTrue(validate(root / "task.json", submission)["valid"])
            report["requirements"][0]["evidence"] = []
            (submission / "report.json").write_text(json.dumps(report), encoding="utf-8")
            with self.assertRaises(ValueError):
                validate(root / "task.json", submission)

    def test_fixture_source_is_stable_per_seed_and_varies_between_seeds(self):
        first = source_for(9)
        self.assertEqual(first, source_for(9))
        self.assertNotEqual(first, source_for(10))

    def test_comparison_keeps_gate_pass_rate_and_process_metrics(self):
        rubric = read_json(BENCHMARK / "rubric.json")
        clean = score(self.assessment(), rubric)
        failed_assessment = self.assessment()
        failed_assessment["metrics"]["run_id"] = "run-2"
        failed_assessment["gates"][rubric["gates"][0]["id"]]["passed"] = False
        failed = score(failed_assessment, rubric)
        result = aggregate([clean, failed])["models"][0]
        self.assertEqual(result["run_count"], 2)
        self.assertEqual(result["all_gates_pass_rate"], 0.5)
        self.assertTrue(result["pass_at_1"])


if __name__ == "__main__":
    unittest.main()
