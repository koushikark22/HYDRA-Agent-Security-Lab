from dataclasses import replace
from pathlib import Path

from hydra_lab.config import Settings
from hydra_lab.experiment import run_experiment


def test_offline_end_to_end(tmp_path: Path):
    settings = Settings()
    settings = replace(
        settings,
        offline=True,
        results_dir=tmp_path / "results",
        train_path=Path("data/train.jsonl"),
        test_path=Path("data/test.jsonl"),
    )
    out = run_experiment(settings)
    assert (out / "manifest.json").exists()
    assert (out / "comparison.json").exists()
    assert (out / "policy.txt").exists()
