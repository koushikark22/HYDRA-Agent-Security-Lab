from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from .config import Settings
from .experiment import run_experiment


def run_repeatability(settings: Settings, attempts: int = 5) -> Path:
    if not 2 <= attempts <= 20:
        raise ValueError("attempts must be between 2 and 20")
    if settings.offline:
        raise ValueError("Repeatability requires live Nebius; offline mode is not allowed")
    batch = settings.results_dir / ("repeatability_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    batch.mkdir(parents=True, exist_ok=False)
    records = []
    for index in range(1, attempts + 1):
        before = {p.name for p in settings.results_dir.iterdir() if p.is_dir()}
        row = {"attempt": index, "status": "error", "run_id": None, "policy_valid": False}
        try:
            path = run_experiment(settings)
            row["run_id"] = path.name
            row["status"] = "completed"
            validation = path / "policy_validation.json"
            row["policy_valid"] = validation.exists() and json.loads(validation.read_text(encoding="utf-8")).get("status") == "valid"
            comparison = json.loads((path / "comparison.json").read_text(encoding="utf-8"))
            row["baseline"] = comparison["baseline"]
            row["defended"] = comparison["defended"]
            row["policy_hash"] = json.loads((path / "manifest.json").read_text(encoding="utf-8"))["policy_hash"]
        except Exception as exc:
            row["error"] = f"{type(exc).__name__}: {exc}"
            after = [p for p in settings.results_dir.iterdir() if p.is_dir() and p.name not in before and p != batch]
            if len(after) == 1:
                row["run_id"] = after[0].name
                validation = after[0] / "policy_validation.json"
                if validation.exists():
                    try:
                        row["validation"] = json.loads(validation.read_text(encoding="utf-8"))
                    except (ValueError, OSError):
                        pass
        records.append(row)
        (batch / "attempts.json").write_text(json.dumps(records, indent=2), encoding="utf-8")
        print(f"Attempt {index}/{attempts}: {row['status']} | policy_valid={row['policy_valid']} | run={row['run_id']}", flush=True)
    completed = [r for r in records if r["status"] == "completed" and r["policy_valid"]]
    summary = {
        "attempts": attempts,
        "valid_policy_count": len(completed),
        "valid_policy_rate": len(completed) / attempts,
        "security_failure_free_count": sum(r["defended"]["security_failure_rate"] == 0 for r in completed),
        "security_failure_free_rate_all_attempts": sum(r["defended"]["security_failure_rate"] == 0 for r in completed) / attempts,
        "note": "Invalid policies and runtime errors count against end-to-end reliability; security metrics apply only to completed validated evaluations.",
    }
    (batch / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2), flush=True)
    return batch

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--attempts", type=int, default=5)
    args = parser.parse_args()
    run_repeatability(Settings(), args.attempts)
