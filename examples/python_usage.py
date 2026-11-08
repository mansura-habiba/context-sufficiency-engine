"""Run as `python examples/python_usage.py` after `pip install -e .`."""
import json
from pathlib import Path

from cse import CompilationRequest, ContextCompiler

request = CompilationRequest.parse(json.loads(Path("examples/incident.json").read_text()))
result = ContextCompiler().compile(request)
print("status:", result.status)
print("selected evidence:", ", ".join(result.selected_ids))
print("estimated tokens:", result.estimated_tokens)
print("context:", result.context_json)
