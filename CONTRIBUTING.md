# Contributing

Thank you for helping build a reproducible, evidence-led context engine.

1. Discuss substantial architecture or model changes in a GitHub issue before implementing them.
2. Add a regression test for every policy, ACL, dependency, budget, or model-boundary change.
3. Keep the default path offline and dependency-light; make model/serving providers optional.
4. Do not submit real tenant content, credentials, private model outputs, or identifiable personal information in issues or fixtures.
5. State whether an evaluation uses training data, held-out samples, or downstream verified task outcomes.

Run `python -m unittest discover -s tests -v` and `python -m cse benchmark examples/eval_cases.json` before submitting a PR.

Apache-2.0 licensing applies to contributed code. Do not add external datasets or model weights without verifying their licences and permitted use.
