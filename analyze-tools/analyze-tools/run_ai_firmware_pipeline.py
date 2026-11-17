#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_ai_firmware_pipeline_v3.py

One-command SSCS AI-firmware pipeline.

Stages:
  01_ai_firmware_extract_profile.py
      download/materialize -> extract -> model extraction/profile -> raw SDK evidence
  02_third_party_component_identify.py
      raw SDK evidence + extracted tree -> precise + broad component inventories
  03_nvd_vulnerability_match.py
      precise inventory + local NVD -> high-relevance vulnerability candidates

Final outputs:
  <work-dir>/final_results/model_extraction_results.csv
  <work-dir>/final_results/third_party_components_precise.csv
  <work-dir>/final_results/third_party_components_broad.csv
  <work-dir>/final_results/high_relevance_vulnerability_candidates.csv
  retained_models/ retained_static_models/ retained_sdk_libs/ if available
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def run(cmd, dry_run: bool = False) -> None:
    print("\n$", " ".join(str(x) for x in cmd), flush=True)
    if dry_run:
        return
    proc = subprocess.run([str(x) for x in cmd])
    if proc.returncode != 0:
        raise SystemExit(proc.returncode)


def copy_if_exists(src: Path, dst: Path) -> None:
    if src.exists():
        ensure_dir(dst.parent)
        shutil.copy2(src, dst)
    else:
        print(f"[warn] missing expected output: {src}", file=sys.stderr)


def main() -> int:
    ap = argparse.ArgumentParser(description="Run SSCS AI firmware model/component/NVD pipeline")
    ap.add_argument("-i", "--input", required=True, help="CSV with Model, Version, DownloadLink")
    ap.add_argument("--work-dir", required=True, help="working directory")
    ap.add_argument("--nvd-dir", required=True, help="directory with NVD nvdcve-2.0-YYYY.json.gz files")
    ap.add_argument("--script-dir", default=".", help="directory containing stage 01/02/03 scripts")
    ap.add_argument("--python", default=sys.executable or "/usr/bin/python3")
    ap.add_argument("--redownload", action="store_true")
    ap.add_argument("--reextract", action="store_true")
    ap.add_argument("--no-git-lfs", action="store_true")
    ap.add_argument("--binwalk", action="store_true", help="enable optional binwalk extraction in stage 01")
    ap.add_argument("--retain-all-libs", action="store_true", help="retain every discovered library in stage 01")
    ap.add_argument("--kernel-relevance-levels", default="HIGH", help="passed to stage 03; e.g. HIGH or HIGH,MEDIUM")
    ap.add_argument("--max-samples", type=int, default=0)
    ap.add_argument("--debug", action="store_true", help="write optional debug evidence tables")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--cleanup-extracted-after", action="store_true", help="delete extracted tree after stage 03")
    args = ap.parse_args()

    work = Path(args.work_dir)
    downloads = work / "downloads"
    extracted = work / "extracted"
    profile = work / "profile_results"
    sdk = work / "sdk_results"
    vuln = work / "vuln_results"
    final = work / "final_results"
    for path in [downloads, extracted, profile, sdk, vuln, final]:
        ensure_dir(path)

    script_dir = Path(args.script_dir)
    s1 = script_dir / "01_ai_firmware_extract_profile.py"
    s2 = script_dir / "02_third_party_component_identify.py"
    s3 = script_dir / "03_nvd_vulnerability_match.py"
    for script in [s1, s2, s3]:
        if not script.exists():
            raise SystemExit(f"pipeline script not found: {script}")

    # Stage 01 must keep extracted files until stages 02 and 03 have completed.
    cmd1 = [
        args.python, s1,
        "-i", args.input,
        "-o", profile,
        "--download-dir", downloads,
        "--extract-dir", extracted,
        "--keep-files",
    ]
    if args.redownload:
        cmd1.append("--redownload")
    if args.reextract:
        cmd1.append("--reextract")
    if args.no_git_lfs:
        cmd1.append("--no-git-lfs")
    if args.binwalk:
        cmd1.append("--binwalk")
    if args.retain_all_libs:
        cmd1.append("--retain-all-libs")
    if args.debug:
        cmd1.append("--debug")
    if args.max_samples:
        cmd1.extend(["--max-samples", str(args.max_samples)])
    run(cmd1, dry_run=args.dry_run)

    sdk_raw = profile / "third_party_sdk_inventory_raw.csv"
    if not args.dry_run and not sdk_raw.exists():
        raise SystemExit(f"stage 01 did not produce {sdk_raw}")

    cmd2 = [
        args.python, s2,
        "--sdk-raw", sdk_raw,
        "--extract-dir", extracted,
        "--retained-dir", profile / "retained_sdk_libs",
        "-o", sdk,
    ]
    if args.debug:
        cmd2.append("--debug")
    run(cmd2, dry_run=args.dry_run)

    precise = sdk / "third_party_components_precise.csv"
    if not args.dry_run and not precise.exists():
        raise SystemExit(f"stage 02 did not produce {precise}")

    cmd3 = [
        args.python, s3,
        "--inventory", precise,
        "--extract-dir", extracted,
        "--nvd-dir", args.nvd_dir,
        "-o", vuln,
        "--kernel-relevance-levels", args.kernel_relevance_levels,
    ]
    run(cmd3, dry_run=args.dry_run)

    if not args.dry_run:
        outputs = [
            (profile / "model_extraction_results.csv", final / "model_extraction_results.csv"),
            (profile / "distinct_model_files.csv", final / "distinct_model_files.csv"),
            (profile / "distinct_model_file_summary.csv", final / "distinct_model_file_summary.csv"),
            (sdk / "third_party_components_precise.csv", final / "third_party_components_precise.csv"),
            (sdk / "third_party_components_broad.csv", final / "third_party_components_broad.csv"),
            (vuln / "high_relevance_vulnerability_candidates.csv", final / "high_relevance_vulnerability_candidates.csv"),
        ]
        for src, dst in outputs:
            copy_if_exists(src, dst)

        for name in ["retained_models", "retained_static_models", "retained_sdk_libs"]:
            src = profile / name
            dst = final / name
            if src.exists():
                if dst.exists():
                    shutil.rmtree(dst)
                shutil.copytree(src, dst)

        if args.cleanup_extracted_after and extracted.exists():
            shutil.rmtree(extracted)
            print(f"[cleanup] removed extracted tree: {extracted}")

    print("\n========== Pipeline complete ==========")
    print(f"final results: {final}")
    print("  - model_extraction_results.csv")
    print("  - third_party_components_precise.csv")
    print("  - third_party_components_broad.csv")
    print("  - high_relevance_vulnerability_candidates.csv")
    print("  - retained_models/ retained_static_models/ retained_sdk_libs/ if available")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
