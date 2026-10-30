from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .config import Settings
from .dataset import load_jsonl
from .evaluator import run_cases
from .metrics import defensive_training_summary, summarize
from .policy import NebiusPolicyGenerator
from .agent import parse_policy_controls


def _write_jsonl(path: Path, records) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(record.model_dump_json() + "\n")


def _delta(before: float, after: float) -> float:
    return round(after - before, 4)


def run_experiment(settings: Settings) -> Path:
    train = load_jsonl(settings.train_path)
    test = load_jsonl(settings.test_path)

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:6]
    out_dir = settings.results_dir / run_id
    out_dir.mkdir(parents=True, exist_ok=False)

    baseline_train = run_cases(
        train,
        synthetic_secret=settings.synthetic_secret,
        policy="",
    )
    baseline_test = run_cases(
        test,
        synthetic_secret=settings.synthetic_secret,
        policy="",
    )

    training_summary = defensive_training_summary(baseline_train)

    generator = NebiusPolicyGenerator(settings)
    artifact = generator.generate(training_summary)
    controls = parse_policy_controls(artifact.policy)
    if not controls.effective:
        missing = [
            key for key in (
                "instruction_data_separation",
                "secret_non_disclosure",
                "public_sink_controls",
                "continue_benign_task",
            )
            if not getattr(controls, key)
        ]
        validation = {
            "status": "invalid_generated_policy",
            "policy_hash": artifact.policy_hash,
            "generated_by_nebius": artifact.generated_by_nebius,
            "controls": vars(controls),
            "missing_required_controls": missing,
        }
        (out_dir / "policy_validation.json").write_text(
            json.dumps(validation, indent=2), encoding="utf-8"
        )
        (out_dir / "policy.txt").write_text(artifact.policy, encoding="utf-8")
        raise RuntimeError(
            "Generated policy did not satisfy required controls: "
            + ", ".join(missing)
            + f". Evaluation aborted; diagnostics: {out_dir / 'policy_validation.json'}"
        )
    (out_dir / "policy_validation.json").write_text(
        json.dumps({"status": "valid", "policy_hash": artifact.policy_hash,
                    "controls": vars(controls)}, indent=2), encoding="utf-8"
    )

    defended_test = run_cases(
        test,
        synthetic_secret=settings.synthetic_secret,
        policy=artifact.policy,
    )

    baseline_metrics = summarize(baseline_test)
    defended_metrics = summarize(defended_test)

    comparison = {
        "baseline": baseline_metrics,
        "defended": defended_metrics,
        "delta": {
            "security_failure_rate": _delta(
                baseline_metrics["security_failure_rate"],
                defended_metrics["security_failure_rate"],
            ),
            "secret_disclosure_rate": _delta(
                baseline_metrics["secret_disclosure_rate"],
                defended_metrics["secret_disclosure_rate"],
            ),
            "benign_task_success_rate": _delta(
                baseline_metrics["benign_task_success_rate"],
                defended_metrics["benign_task_success_rate"],
            ),
            "false_positive_refusal_rate": _delta(
                baseline_metrics["false_positive_refusal_rate"],
                defended_metrics["false_positive_refusal_rate"],
            ),
        },
    }

    manifest = {
        "run_id": run_id,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "project": "HYDRA AI Agent Security Lab",
        "workflow": [
            "baseline training evaluation",
            "aggregate defensive failure summary",
            "Nebius/Nemotron defensive policy generation",
            "frozen held-out evaluation",
            "deterministic security/utility comparison",
        ],
        "nebius": {
            "runtime_call_used": artifact.generated_by_nebius,
            "provider": artifact.provider,
            "model": artifact.model,
            "base_url": artifact.base_url,
        },
        "policy_hash": artifact.policy_hash,
        "safety_boundary": {
            "synthetic_secret_only": True,
            "mock_tools_only": True,
            "frozen_adversarial_corpus": True,
            "attack_generation": False,
            "attack_optimization": False,
        },
        "train_cases": len(train),
        "heldout_test_cases": len(test),
    }

    _write_jsonl(out_dir / "baseline_train.jsonl", baseline_train)
    _write_jsonl(out_dir / "baseline_test.jsonl", baseline_test)
    _write_jsonl(out_dir / "defended_test.jsonl", defended_test)

    (out_dir / "policy.txt").write_text(artifact.policy, encoding="utf-8")
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )
    (out_dir / "comparison.json").write_text(
        json.dumps(comparison, indent=2),
        encoding="utf-8",
    )
    (out_dir / "training_summary.json").write_text(
        json.dumps(training_summary, indent=2),
        encoding="utf-8",
    )

    return out_dir
