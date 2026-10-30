from __future__ import annotations

import json
from pathlib import Path
from .schema import EvalCase


def load_jsonl(path: str | Path) -> list[EvalCase]:
    records: list[EvalCase] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(EvalCase.model_validate(json.loads(line)))
            except Exception as exc:
                raise ValueError(f"Invalid JSONL at {path}:{line_number}: {exc}") from exc
    return records
