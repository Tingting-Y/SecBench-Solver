"""Entry point for the SEC-bench multi-agent vulnerability solver.

Usage:
    # Run all instances
    python main.py

    # Run a specific instance
    python main.py --instance_id gpac.cve-2023-42298

    # Run a range of instances
    python main.py --start 0 --end 10
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timezone

from datasets import load_dataset

from agents import create_model_client
from config import RESULTS_DIR, INSTANCE_TIMEOUT
from pipeline import solve_instance

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(
            os.path.join(RESULTS_DIR, "solver.log"), mode="a"
        ),
    ],
)
# Suppress autogen_core.events — it serialises full LLM conversation history
# (including system prompts and tool results) into single log lines, producing
# 100KB+ lines that bloat the log to ~50MB per instance and can OOM the process.
logging.getLogger("autogen_core.events").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)


def save_result(result: dict) -> None:
    """Save a single instance result to a JSON file."""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    instance_id = result.get("instance_id", "unknown")
    # Sanitize filename
    safe_name = instance_id.replace("/", "_").replace("\\", "_")
    path = os.path.join(RESULTS_DIR, f"{safe_name}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    logger.info("Result saved to %s", path)

    # Also save the patch separately if successful
    if result.get("status") == "success" and result.get("patch"):
        patch_path = os.path.join(RESULTS_DIR, f"{safe_name}.diff")
        with open(patch_path, "w", encoding="utf-8") as f:
            f.write(result["patch"])
        logger.info("Patch saved to %s", patch_path)


def print_summary(results: list[dict]) -> None:
    """Print a summary of all results."""
    total = len(results)
    success = sum(1 for r in results if r.get("status") == "success")
    failed = sum(1 for r in results if r.get("status") == "failed")
    errors = sum(1 for r in results if r.get("status") == "error")
    build_failed = sum(1 for r in results if r.get("status") == "build_failed")

    print("\n" + "=" * 60)
    print("SEC-bench Adversarial Solver Summary")
    print("=" * 60)
    print(f"Total instances:    {total}")
    if total:
        print(f"Successfully fixed: {success} ({100*success/total:.1f}%)")
    print(f"Patch failed:       {failed}")
    print(f"Build failed:       {build_failed}")
    print(f"Errors:             {errors}")
    print("=" * 60)

    if success > 0:
        successful = [r for r in results if r.get("status") == "success"]
        avg_rounds = sum(r.get("selected_round", 1) for r in successful) / success
        avg_candidates = sum(r.get("num_candidates", 1) for r in successful) / success
        print(f"Avg selected round:  {avg_rounds:.1f}")
        print(f"Avg candidates:      {avg_candidates:.1f}")

    # Print details for failed/error instances
    problem_instances = [
        r for r in results if r.get("status") != "success"
    ]
    if problem_instances:
        print(f"\nFailed/Error instances ({len(problem_instances)}):")
        for r in problem_instances:
            print(f"  - {r.get('instance_id', '?')}: {r.get('status', '?')}")


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="SEC-bench multi-agent vulnerability solver"
    )
    parser.add_argument(
        "--instance_id",
        type=str,
        default=None,
        help="Run a specific instance by its ID",
    )
    parser.add_argument(
        "--start",
        type=int,
        default=None,
        help="Start index for range of instances",
    )
    parser.add_argument(
        "--end",
        type=int,
        default=None,
        help="End index (exclusive) for range of instances",
    )
    args = parser.parse_args()

    # Ensure results directory exists
    os.makedirs(RESULTS_DIR, exist_ok=True)

    logger.info("Loading SEC-bench dataset...")
    ds = load_dataset("SEC-bench/SEC-bench")["cve"]
    logger.info("Loaded %d instances", len(ds))

    # Filter instances based on CLI arguments
    if args.instance_id:
        instances = [row for row in ds if row["instance_id"] == args.instance_id]
        if not instances:
            logger.error("Instance %s not found in dataset", args.instance_id)
            sys.exit(1)
        logger.info("Running single instance: %s", args.instance_id)
    else:
        instances = list(ds)
        if args.start is not None or args.end is not None:
            start = args.start or 0
            end = args.end or len(instances)
            instances = instances[start:end]
            logger.info("Running instances [%d, %d)", start, end)
        else:
            logger.info("Running all %d instances", len(instances))

    # Create shared model client
    model_client = create_model_client()

    # Process instances sequentially
    results = []
    start_time = datetime.now(timezone.utc)

    for i, instance in enumerate(instances):
        instance_id = instance["instance_id"]
        logger.info(
            "Processing instance %d/%d: %s", i + 1, len(instances), instance_id
        )

        # Skip if already solved
        safe_name = instance_id.replace("/", "_").replace("\\", "_")
        result_path = os.path.join(RESULTS_DIR, f"{safe_name}.json")
        if os.path.exists(result_path):
            logger.info("Skipping %s (already processed)", instance_id)
            with open(result_path, "r") as f:
                results.append(json.load(f))
            continue

        try:
            result = await asyncio.wait_for(
                solve_instance(instance, model_client, results_dir=RESULTS_DIR),
                timeout=INSTANCE_TIMEOUT,
            )
        except asyncio.TimeoutError:
            logger.error(
                "Instance %s timed out after %d seconds", instance_id, INSTANCE_TIMEOUT
            )
            result = {
                "instance_id": instance_id,
                "status": "timeout",
                "error": f"Timed out after {INSTANCE_TIMEOUT}s",
            }
        except Exception as e:
            logger.exception("Unhandled exception for %s — skipping", instance_id)
            result = {
                "instance_id": instance_id,
                "status": "error",
                "error": str(e),
            }
        save_result(result)
        results.append(result)

    elapsed = datetime.now(timezone.utc) - start_time
    logger.info("Total elapsed time: %s", elapsed)
    print_summary(results)


if __name__ == "__main__":
    asyncio.run(main())
