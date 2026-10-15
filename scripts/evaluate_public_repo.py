"""Read-only static crypto-pattern scan of a public GitHub repository.

Downloads a source archive and scans local text files only. Download time and scanner
execution time are reported separately. Precision/recall are withheld unless a complete
human-reviewed ground-truth CSV is supplied and explicitly marked complete.
"""
from __future__ import annotations

import argparse
import csv
import json
import tarfile
import tempfile
import time
import sys
from pathlib import Path, PurePosixPath
from urllib.parse import quote
from urllib.request import Request, urlopen

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
from src.discovery import discover_directory

GROUND_TRUTH_COLUMNS = {"path", "algorithm", "is_present", "reviewed", "repository", "ref"}


def calculate_metrics(detections, annotations):
    """Calculate metrics from (path, algorithm) pairs and reviewed truth labels."""
    detection_set = set(detections)
    if not detection_set.issubset(annotations):
        missing = sorted(detection_set - set(annotations))
        raise ValueError(f"Every detected pair must be reviewed; missing labels: {missing[:5]}")
    positives = {pair for pair, present in annotations.items() if present}
    tp = len(detection_set & positives)
    fp = len(detection_set - positives)
    fn = len(positives - detection_set)
    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
    }


def _read_ground_truth(path, expected_repo, expected_ref):
    annotations = {}
    with Path(path).open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or not GROUND_TRUTH_COLUMNS.issubset(reader.fieldnames):
            raise ValueError(f"Ground-truth CSV must contain columns: {sorted(GROUND_TRUTH_COLUMNS)}")
        for line_number, row in enumerate(reader, start=2):
            rel_path = row["path"].replace("\\", "/").strip()
            algorithm = row["algorithm"].strip()
            if row["repository"].strip() != expected_repo or row["ref"].strip() != expected_ref:
                raise ValueError(
                    f"Ground-truth line {line_number} targets "
                    f"{row['repository']!r}@{row['ref']!r}, expected {expected_repo!r}@{expected_ref!r}"
                )
            if not rel_path or not algorithm:
                raise ValueError(f"Empty path or algorithm on ground-truth line {line_number}")
            if row["reviewed"].strip().lower() not in {"true", "1", "yes"}:
                raise ValueError(f"Ground-truth line {line_number} is not marked reviewed")
            value = row["is_present"].strip().lower()
            if value not in {"true", "false", "1", "0", "yes", "no"}:
                raise ValueError(f"Invalid is_present value on ground-truth line {line_number}")
            key = (rel_path, algorithm)
            if key in annotations:
                raise ValueError(f"Duplicate ground-truth pair on line {line_number}: {key}")
            annotations[key] = value in {"true", "1", "yes"}
    if not annotations:
        raise ValueError("Ground-truth CSV is empty; a complete audit needs reviewed rows")
    return annotations


def _download_and_extract(repo, ref, destination):
    parts = repo.split("/")
    if len(parts) != 2 or any(not p or p in {".", ".."} for p in parts):
        raise ValueError("--repo must be in OWNER/REPOSITORY format")
    archive_url = f"https://codeload.github.com/{quote(parts[0], safe='')}/{quote(parts[1], safe='')}/tar.gz/{quote(ref, safe='')}"
    request = Request(archive_url, headers={"User-Agent": "crypto-inventory-migration-planner-evaluator/1.0"})
    with urlopen(request, timeout=60) as response:
        archive_bytes = response.read()
    archive_path = Path(destination) / "source.tar.gz"
    archive_path.write_bytes(archive_bytes)
    with tarfile.open(archive_path, "r:gz") as archive:
        safe_members = []
        for member in archive.getmembers():
            member_path = PurePosixPath(member.name)
            if member_path.is_absolute() or ".." in member_path.parts:
                continue
            if member.isfile() or member.isdir():
                safe_members.append(member)
        archive.extractall(destination, members=safe_members, filter="data")
    roots = [p for p in Path(destination).iterdir() if p.is_dir() and p.name != "__pycache__"]
    if len(roots) != 1:
        raise ValueError("Could not identify one source root in the GitHub archive")
    return roots[0], len(archive_bytes)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="Public GitHub repository as OWNER/REPOSITORY")
    parser.add_argument("--ref", default="main", help="Branch, tag, or commit (default: main)")
    parser.add_argument("--output-dir", default="results/tables", help="Directory for CSV/JSON outputs")
    parser.add_argument("--ground-truth", help="Reviewed CSV with repository,ref,path,algorithm,is_present,reviewed")
    parser.add_argument("--ground-truth-complete", action="store_true", help="Assert the audited scope is complete")
    args = parser.parse_args()
    if args.ground_truth_complete and not args.ground_truth:
        parser.error("--ground-truth-complete requires --ground-truth")
    if args.ground_truth and not args.ground_truth_complete:
        parser.error("Partial audits cannot produce metrics; use --ground-truth-complete only after full review")

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="crypto-scan-") as temp_dir:
        download_start = time.perf_counter()
        source_root, archive_bytes = _download_and_extract(args.repo, args.ref, temp_dir)
        download_seconds = time.perf_counter() - download_start
        scan_start = time.perf_counter()
        findings = discover_directory(source_root)
        scan_seconds = time.perf_counter() - scan_start
        findings.to_csv(output_dir / "public_repo_scan_findings.csv", index=False)
        detections = {
            (str(row.evidence_source).replace("\\", "/"), str(row.algorithm))
            for row in findings.itertuples(index=False)
        }
        # Seed a review worksheet from every candidate pair. Reviewers must set
        # is_present/reviewed and add any missed positive pairs before scoring.
        template_path = output_dir / "public_repo_ground_truth_template.csv"
        with template_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["repository", "ref", "path", "algorithm", "is_present", "reviewed"],
            )
            writer.writeheader()
            for rel_path, algorithm in sorted(detections):
                writer.writerow({
                    "repository": args.repo,
                    "ref": args.ref,
                    "path": rel_path,
                    "algorithm": algorithm,
                    "is_present": "",
                    "reviewed": "false",
                })
        summary = {
            "repository": args.repo,
            "ref": args.ref,
            "archive_bytes": archive_bytes,
            "download_seconds": round(download_seconds, 6),
            "scanner_execution_seconds": round(scan_seconds, 6),
            "candidate_findings": len(detections),
            "ground_truth_template": str(template_path),
            "files_with_findings": int(findings["evidence_source"].nunique()) if not findings.empty else 0,
            "evaluation_status": "pending_manual_ground_truth",
            "precision": None,
            "recall": None,
            "limitations": [
                "Regex-based candidate discovery, not a complete cryptographic inventory.",
                "No repository code is executed; only readable files under the downloaded source root are scanned.",
                "Precision/recall require manual labels for detections and missed true findings.",
            ],
        }
        if args.ground_truth:
            annotations = _read_ground_truth(args.ground_truth, args.repo, args.ref)
            summary.update(calculate_metrics(detections, annotations))
            summary["evaluation_status"] = "human_ground_truth_scored"
            summary["ground_truth_rows"] = len(annotations)
            summary["ground_truth_file"] = str(Path(args.ground_truth))
            summary["ground_truth_complete_asserted_by_operator"] = True
        (output_dir / "public_repo_scan_summary.json").write_text(
            json.dumps(summary, indent=2) + "\n", encoding="utf-8"
        )
        print(json.dumps(summary, indent=2))
        print(f"Findings CSV: {output_dir / 'public_repo_scan_findings.csv'}")
        print(f"Summary JSON: {output_dir / 'public_repo_scan_summary.json'}")


if __name__ == "__main__":
    main()
