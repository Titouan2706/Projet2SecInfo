"""Run the CICIDS2017 download, preprocessing and asset classification pipeline."""

import argparse
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parent
SCRIPTS = ROOT / "scripts"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-download", action="store_true", help="use existing input files")
    parser.add_argument("--pcap", action="store_true", help="also download raw PCAPs (about 52 GB)")
    parser.add_argument("--input", type=Path, default=ROOT / "data" / "cicids2017" / "traffic_labels",
                        help="TrafficLabelling CSV or Parquet directory")
    parser.add_argument("--processed", type=Path, default=ROOT / "processed",
                        help="directory for preprocessed outputs")
    parser.add_argument("--output", type=Path, default=ROOT / "outputs",
                        help="directory for asset classification outputs")
    args = parser.parse_args()
    if args.skip_download and args.pcap:
        parser.error("--pcap cannot be used with --skip-download")

    stages = []
    if not args.skip_download:
        stages.append([sys.executable, str(SCRIPTS / "download_cicids2017.py")]
                      + (["--pcap"] if args.pcap else []))
    stages.extend([
        [sys.executable, str(SCRIPTS / "preprocessing.py"),
         "--input", str(args.input), "--output", str(args.processed)],
        [sys.executable, str(SCRIPTS / "agent_discovery_classification.py"),
         "--processed", str(args.processed), "--output", str(args.output)],
    ])
    for command in stages:
        print(f"\nRunning {Path(command[1]).name}...", flush=True)
        subprocess.run(command, check=True, cwd=ROOT)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        print(f"Pipeline stopped: {Path(error.cmd[1]).name} exited with code {error.returncode}",
              file=sys.stderr)
        sys.exit(error.returncode)
