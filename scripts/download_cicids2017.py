#!/usr/bin/env python3
"""Download CICIDS2017 network flows from a public mirror."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import sys
import tempfile
from urllib.parse import quote
from urllib.request import urlopen


REVISION = "70bac6246d99cf046186a02e1cce6883e2ffe7ea"
REPOSITORY = "https://huggingface.co/datasets/bvsam/cic-ids-2017"
API = f"https://huggingface.co/api/datasets/bvsam/cic-ids-2017/tree/{REVISION}"
DESTINATION = Path(__file__).resolve().parent.parent / "data" / "cicids2017"
EXPECTED_COUNTS = {"machine_learning": 8, "traffic_labels": 8, "pcap": 5}


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(entry, directory):
    source_path = PurePosixPath(entry["path"])
    target = directory / source_path.name
    expected_hash = entry["lfs"]["oid"]

    if target.exists():
        if sha256(target) != expected_hash:
            raise ValueError(f"{target} already exists but its SHA-256 does not match; remove it and retry")
        print(f"Already downloaded: {target}", flush=True)
        return

    directory.mkdir(parents=True, exist_ok=True)
    url = f"{REPOSITORY}/resolve/{REVISION}/{quote(entry['path'])}"
    print(f"Downloading {entry['path']}...", flush=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(dir=directory, suffix=".part", delete=False) as output:
            temporary_path = Path(output.name)
            digest = hashlib.sha256()
            with urlopen(url, timeout=60) as response:
                for chunk in iter(lambda: response.read(1024 * 1024), b""):
                    output.write(chunk)
                    digest.update(chunk)
        if digest.hexdigest() != expected_hash:
            raise ValueError(f"SHA-256 mismatch for {entry['path']}")
        os.replace(temporary_path, target)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--pcap", action="store_true",
        help="also download the five raw packet captures (about 52 GB)",
    )
    args = parser.parse_args()

    categories = ["traffic_labels", "machine_learning"]
    if args.pcap:
        categories.append("pcap")

    with urlopen(f"{API}?recursive=true", timeout=60) as response:
        entries = json.load(response)

    for category in categories:
        files = [
            entry for entry in entries
            if entry["type"] == "file"
            and len(PurePosixPath(entry["path"]).parts) == 2
            and PurePosixPath(entry["path"]).parts[0] == category
            and entry["path"].endswith(".pcap" if category == "pcap" else ".parquet")
        ]
        if len(files) != EXPECTED_COUNTS[category] or any("lfs" not in entry for entry in files):
            raise ValueError(f"Unexpected file listing for {category}")
        for entry in files:
            download(entry, DESTINATION / category)

    print(f"Dataset available in {DESTINATION}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError) as error:
        print(f"Download failed: {error}", file=sys.stderr)
        sys.exit(1)
