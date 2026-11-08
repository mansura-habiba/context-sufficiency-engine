"""Offline-only, dependency-free experimental CPU model training."""
from __future__ import annotations

import json
import math
import random
from pathlib import Path

from cse.models import InvalidRequest
from cse.scorers import HashedLinearScorer


def load_examples(path: str) -> list[dict]:
    samples = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        data = json.loads(line)
        if (not isinstance(data, dict)
                or any(not isinstance(data.get(x), str) for x in ("task", "title", "content"))
                or type(data.get("label")) is not int or data["label"] not in (0, 1)):
            raise InvalidRequest("each training row needs task/title/content and binary label")
        samples.append(data)
    if len(samples) < 4 or {s["label"] for s in samples} != {0, 1}:
        raise InvalidRequest("training requires at least four positive/negative examples")
    return samples


def train(path: str, *, epochs: int = 30, learning_rate: float = 0.06,
          dimensions: int = 4096, seed: int = 19) -> tuple[HashedLinearScorer, dict]:
    if epochs < 1 or epochs > 1000 or not (0 < learning_rate < 1):
        raise InvalidRequest("invalid training parameters")
    samples = load_examples(path)
    rng = random.Random(seed)
    weights: dict[int, float] = {}
    bias = 0.0
    for epoch in range(epochs):
        order = list(range(len(samples)))
        rng.shuffle(order)
        rate = learning_rate / (1 + 0.04 * epoch)
        for row in order:
            sample = samples[row]
            f = HashedLinearScorer.features(
                sample["task"], sample["title"], sample["content"], dimensions
            )
            z = max(-30, min(30, bias + sum(weights.get(k, 0.0) * v for k, v in f.items())))
            error = 1 / (1 + math.exp(-z)) - sample["label"]
            for k, v in f.items():
                weights[k] = weights.get(k, 0.0) - rate * (error * v + 0.0001 * weights.get(k, 0.0))
            bias -= rate * error
    model = HashedLinearScorer(weights, bias, dimensions)
    accuracy = sum(
        (model.predict(s["task"], s["title"], s["content"]) >= 0.5) == bool(s["label"])
        for s in samples
    ) / len(samples)
    return model, {"training_examples": len(samples), "training_accuracy": round(accuracy, 4),
                   "warning": "training accuracy is not held-out evaluation"}
