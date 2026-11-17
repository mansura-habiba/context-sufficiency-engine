"""Tests for the deterministic pilot (no model execution or security efficacy claim)."""
from __future__ import annotations
import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("pilot.py")
spec = importlib.util.spec_from_file_location("cse_threatbench_pilot", SCRIPT)
module = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class PilotTests(unittest.TestCase):
    def test_exact_matrix(self):
        output = module.run()
        self.assertEqual(output["task_templates"], 12)
        self.assertEqual(output["observations"], 72)
        self.assertEqual(len({(x["task_id"], x["variant"]) for x in output["rows"]}), 24)

    def test_paired_cases_preserve_intent(self):
        for task in module.TASKS:
            clean, oc = module.make_case(task, False)
            attack, oa = module.make_case(task, True)
            self.assertEqual(clean["task"], attack["task"])
            self.assertEqual(clean["principal"], attack["principal"])
            self.assertEqual(oc["required_evidence"], oa["required_evidence"])
            self.assertEqual(clean["requirements"], attack["requirements"])
            self.assertGreater(len(attack["items"]), len(clean["items"]))

    def test_no_oracle_required_ids_in_declared_requirements(self):
        for task in module.TASKS:
            request, oracle = module.make_case(task, False)
            declared = {x for r in request["requirements"] for x in r["any_of"]}
            self.assertNotEqual(declared, set(oracle["required_evidence"]))
            self.assertEqual(declared, {task.source})
            self.assertNotIn(task.prerequisite, declared)

    def test_no_real_agent_claims(self):
        output = module.run()
        self.assertEqual(output["status"], "deterministic_selection_only")
        self.assertTrue(all(not row["agent_executed"] for row in output["rows"]))

    def test_foreign_evidence_not_in_policy_baseline_or_cse(self):
        output = module.run()
        for row in output["rows"]:
            if row["attack"] == "A1" and row["system"] != "S0_lexical":
                self.assertFalse(row["forbidden_evidence_selected"])


if __name__ == "__main__":
    unittest.main()
