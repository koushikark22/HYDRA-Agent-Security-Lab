from __future__ import annotations

from .agent import ToyAgent
from .oracle import evaluate
from .schema import EvalCase, EvalRecord
from .tools import MockToolbox


def run_cases(
    cases: list[EvalCase],
    synthetic_secret: str,
    policy: str = "",
) -> list[EvalRecord]:
    agent = ToyAgent(
        toolbox=MockToolbox(synthetic_secret=synthetic_secret),
        policy=policy,
    )

    records: list[EvalRecord] = []
    for case in cases:
        trace = agent.run(case)
        oracle = evaluate(case, trace, synthetic_secret)
        records.append(EvalRecord(case=case, trace=trace, oracle=oracle))
    return records
