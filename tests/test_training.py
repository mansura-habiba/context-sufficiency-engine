import json
import tempfile
import unittest
from pathlib import Path

from cse.scorers import HashedLinearScorer
from cse.training import train
from cse.models import InvalidRequest


class TrainingTests(unittest.TestCase):
    def test_fit_save_load(self):
        rows = [
            {"task": "fix checkout", "title": "checkout incident", "content": "checkout is failing", "label": 1},
            {"task": "fix checkout", "title": "lunch recipe", "content": "bake bread", "label": 0},
            {"task": "audit encryption", "title": "encryption key", "content": "KMS rotation status", "label": 1},
            {"task": "audit encryption", "title": "beach report", "content": "sandcastles", "label": 0},
        ]
        with tempfile.TemporaryDirectory() as folder:
            data_path = Path(folder) / "train.jsonl"
            model_path = Path(folder) / "model.json"
            data_path.write_text("\n".join(json.dumps(row) for row in rows))
            scorer, report = train(str(data_path), epochs=60)
            self.assertEqual(report["training_examples"], 4)
            scorer.save(str(model_path))
            loaded = HashedLinearScorer.load(str(model_path))
            self.assertAlmostEqual(scorer.predict("fix checkout", "checkout incident", "checkout is failing"),
                                   loaded.predict("fix checkout", "checkout incident", "checkout is failing"))

    def test_invalid_training_examples(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "bad.jsonl"
            path.write_text('{"task":"x","title":"x","content":"x","label":1}\n')
            with self.assertRaises(InvalidRequest):
                train(str(path))


if __name__ == "__main__":
    unittest.main()
