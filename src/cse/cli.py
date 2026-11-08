"""CLI. Identity values in files are trusted local demonstration data, not authentication."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cse.benchmark import evaluate
from cse.compiler import ContextCompiler
from cse.models import CompilationRequest, InvalidRequest
from cse.policy import PolicyConfig
from cse.scorers import CloudflareClefScorer, HashedLinearScorer, LexicalScorer
from cse.training import train


def _compiler(args: argparse.Namespace) -> ContextCompiler:
    if args.scorer == "lexical":
        scorer = LexicalScorer()
    elif args.scorer == "linear":
        if not args.model_file:
            raise InvalidRequest("--model-file is required for linear scorer")
        scorer = HashedLinearScorer.load(args.model_file)
    else:
        if not args.allow_external_scoring:
            raise InvalidRequest("--allow-external-scoring is required for Cloudflare")
        scorer = CloudflareClefScorer.from_environment(args.scorer)
    policy = PolicyConfig(
        require_digest=not args.allow_missing_digests,
        external_scoring_allowed=args.allow_external_scoring,
        external_max_classification=args.external_max_classification,
    )
    return ContextCompiler(scorer=scorer, policy=policy)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cse", description="Secure context sufficiency compiler")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("compile", "benchmark"):
        subparser = sub.add_parser(name)
        subparser.add_argument("file", help="JSON request or benchmark cases")
        subparser.add_argument("--scorer", choices=("lexical", "linear", "clef-flash", "clef"), default="lexical")
        subparser.add_argument("--model-file")
        subparser.add_argument("--allow-external-scoring", action="store_true")
        subparser.add_argument("--external-max-classification", choices=("public", "internal", "confidential", "restricted"), default="public")
        subparser.add_argument("--allow-missing-digests", action="store_true")
    trainer = sub.add_parser("train", help="train experimental hashed linear scorer")
    trainer.add_argument("file", help="binary-labelled JSONL")
    trainer.add_argument("--output", required=True)
    trainer.add_argument("--epochs", type=int, default=30)
    args = parser.parse_args(argv)
    try:
        if args.command == "train":
            model, metrics = train(args.file, epochs=args.epochs)
            model.save(args.output)
            print(json.dumps({"model_file": args.output, **metrics}, indent=2))
        elif args.command == "benchmark":
            report = evaluate(_compiler(args), args.file)
            print(json.dumps(report, indent=2))
            return 0 if report["pass_count"] == report["cases"] else 1
        else:
            body = json.loads(Path(args.file).read_text(encoding="utf-8"))
            req = CompilationRequest.parse(body)
            result = _compiler(args).compile(req)
            print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
            return 2 if result.status == "blocked" else 0
        return 0
    except (InvalidRequest, OSError, ValueError) as exc:
        print(f"cse: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
