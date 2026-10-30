from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    synthetic_secret: str = os.getenv("HYDRA_SYNTHETIC_SECRET", "TEST_SECRET_7F3A")
    nebius_api_key: str = os.getenv("NEBIUS_API_KEY", "")
    nebius_base_url: str = os.getenv(
        "NEBIUS_BASE_URL",
        "https://api.tokenfactory.us-central1.nebius.com/v1/",
    )
    nebius_model: str = os.getenv(
        "NEBIUS_MODEL",
        "nvidia/nemotron-3-super-120b-a12b",
    )
    offline: bool = os.getenv("HYDRA_OFFLINE", "0").lower() in {"1", "true", "yes"}
    train_path: Path = Path("data/train.jsonl")
    test_path: Path = Path("data/test.jsonl")
    results_dir: Path = Path("results")
