"""Publish exact-grid sidecars from explicit, already verified artifact directories."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .evidence_artifacts import load_verified_evidence_artifacts
from .exact_grid_artifacts import publish_exact_grid_artifact
from .sweep_artifacts import load_verified_sweep_data


def main() -> None:
    """Parse explicit sources; this command never runs simulation or secure execution."""
    parser = argparse.ArgumentParser(description="Publish verified exact-grid evidence")
    parser.add_argument("--source-sweep-id", required=True)
    parser.add_argument("--sweep-root", default="results/sweeps")
    parser.add_argument("--evidence-dir", action="append", required=True)
    parser.add_argument("--primary-seed", type=int, default=42)
    parser.add_argument("--source-manifest-sha256", required=True)
    parser.add_argument("--source-data-manifest-sha256", required=True)
    parser.add_argument("--output-root", default="results/exact_grid")
    args = parser.parse_args()
    sweep = load_verified_sweep_data(
        Path(args.sweep_root) / args.source_sweep_id, manifest_name="manifest.json"
    )
    evidence_by_point = {}
    for directory in args.evidence_dir:
        evidence = load_verified_evidence_artifacts(directory)
        source_point = evidence.metadata["source_point"]
        key = (source_point["ell"], source_point["seed"])
        if key in evidence_by_point:
            raise ValueError(f"重复 evidence point：{key}")
        evidence_by_point[key] = evidence
    artifacts = publish_exact_grid_artifact(
        verified_sweep=sweep,
        evidence_by_point=evidence_by_point,
        primary_seed=args.primary_seed,
        output_root=args.output_root,
        expected_source_hashes={
            "manifest.json": args.source_manifest_sha256,
            "data_manifest.json": args.source_data_manifest_sha256,
        },
    )
    print(
        json.dumps(
            {
                "artifact_id": artifacts.artifact_id,
                "directory": str(artifacts.directory),
                "manifest_sha256": artifacts.manifest_sha256,
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
