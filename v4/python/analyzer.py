#!/usr/bin/env python3
import sys
import csv
import json
import subprocess
from pathlib import Path
from itertools import repeat
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime

from keyword_scanner import load_weighted_lexicon, find_adjacent_keyword_pairs
from text_extract import extract_text

# -----------------------------
# Config
# -----------------------------

BASE_DIR = Path(__file__).resolve().parent
ENGINE_BIN = BASE_DIR.parent / "engine" / "build" / "boost_regex_runner"
OUTPUT_DIR = BASE_DIR.parent / "output"
OUTPUT_DIR.mkdir(exist_ok=True)

REGEX_FILE = BASE_DIR.parent.parent / "regex_patterns.json"
LEXICON_FILE = BASE_DIR.parent.parent / "lexicon_latest.csv"

MAX_FILE_SIZE_MB = 50


# -----------------------------
# Regex scanning via Boost
# -----------------------------

def run_boost_regex(text: str):
    if not ENGINE_BIN.exists():
        return []

    proc = subprocess.Popen(
        [str(ENGINE_BIN)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    out, _ = proc.communicate(text)
    return out.splitlines()


# -----------------------------
# File scanner (worker-safe)
# -----------------------------

def scan_file_worker(args):
    file_path, regex_patterns, lexicon = args

    results = []
    try:
        if file_path.stat().st_size > MAX_FILE_SIZE_MB * 1024 * 1024:
            return results

        text = extract_text(file_path)
        if not text:
            return results

        # Regex matches
        regex_hits = run_boost_regex(text)
        for hit in regex_hits:
            results.append({
                "type": "regex",
                "pattern": hit,
                "file": file_path.name,
                "path": str(file_path)
            })

        # Keyword pair matches
        keyword_hits = find_adjacent_keyword_pairs(text, lexicon)
        for kw in keyword_hits:
            results.append({
                "type": "keyword_pair",
                "pattern": kw["phrase"],
                "weight": kw["weight"],
                "file": file_path.name,
                "path": str(file_path)
            })

    except Exception as e:
        results.append({
            "type": "error",
            "pattern": str(e),
            "file": file_path.name,
            "path": str(file_path)
        })

    return results


# -----------------------------
# Main
# -----------------------------

def main(argv):
    if not argv:
        print("Usage: analyzer.py <file-or-directory>")
        sys.exit(1)

    target = Path(argv[0]).expanduser().resolve()
    if not target.exists():
        print(f"Path not found: {target}")
        sys.exit(1)

    files = []
    if target.is_file():
        files.append(target)
    else:
        for p in target.rglob("*"):
            if p.is_file():
                files.append(p)

    print(f"[*] Found {len(files)} files")

    with open(REGEX_FILE, "r") as f:
        regex_patterns = json.load(f)

    lexicon = load_weighted_lexicon(LEXICON_FILE)

    all_results = []

    with ProcessPoolExecutor() as pool:
        for file_results in pool.map(
            scan_file_worker,
            zip(files, repeat(regex_patterns), repeat(lexicon))
        ):
            all_results.extend(file_results)

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_file = OUTPUT_DIR / f"purview_candidates_{timestamp}.csv"

    with open(out_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["type", "pattern", "weight", "file", "path"]
        )
        writer.writeheader()

        for row in sorted(
            all_results,
            key=lambda r: r.get("weight", 0),
            reverse=True
        ):
            writer.writerow(row)

    print(f"[✓] Results written to: {out_file}")


if __name__ == "__main__":
    main(sys.argv[1:])