from __future__ import annotations

import argparse
import json
import os
from dataclasses import replace
from pathlib import Path

from openai import OpenAI

from .config import Settings
from .experiment import run_experiment


def cmd_doctor(settings: Settings) -> int:
    print("HYDRA environment check")
    print("-----------------------")
    print(f"Nebius base URL : {settings.nebius_base_url}")
    print(f"NVIDIA model    : {settings.nebius_model}")
    print(f"API key present : {'yes' if settings.nebius_api_key else 'no'}")
    print(f"Offline mode    : {settings.offline}")
    print(f"Train corpus    : {settings.train_path}")
    print(f"Test corpus     : {settings.test_path}")

    if settings.offline:
        print("\nOffline mode enabled; Token Factory will not be called.")
        return 0

    if not settings.nebius_api_key:
        print("\nERROR: NEBIUS_API_KEY is missing.")
        return 2

    try:
        client = OpenAI(
            api_key=settings.nebius_api_key,
            base_url=settings.nebius_base_url,
        )
        models = client.models.list()
        ids = [m.id for m in models.data]
        print(f"Token Factory reachable: yes ({len(ids)} visible models)")
        print(
            "Configured model visible:",
            "yes" if settings.nebius_model in ids else "not confirmed by model listing",
        )
        return 0
    except Exception as exc:
        print(f"\nERROR reaching Token Factory: {type(exc).__name__}: {exc}")
        return 3


def cmd_run(settings: Settings, offline: bool) -> int:
    if offline:
        settings = replace(settings, offline=True)
    out = run_experiment(settings)
    print(f"Completed: {out}")
    print((out / "comparison.json").read_text(encoding="utf-8"))
    return 0


def cmd_show_latest(settings: Settings) -> int:
    if not settings.results_dir.exists():
        print("No results directory yet.")
        return 1

    runs = sorted(p for p in settings.results_dir.iterdir() if p.is_dir())
    if not runs:
        print("No runs yet.")
        return 1

    latest = runs[-1]
    print(f"Latest run: {latest.name}")
    print((latest / "manifest.json").read_text(encoding="utf-8"))
    print((latest / "comparison.json").read_text(encoding="utf-8"))
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="hydra")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("doctor")

    run_parser = sub.add_parser("run")
    run_parser.add_argument("--offline", action="store_true")

    sub.add_parser("show-latest")

    args = parser.parse_args()
    settings = Settings()

    if args.command == "doctor":
        raise SystemExit(cmd_doctor(settings))
    if args.command == "run":
        raise SystemExit(cmd_run(settings, args.offline))
    if args.command == "show-latest":
        raise SystemExit(cmd_show_latest(settings))


if __name__ == "__main__":
    main()
