# Projet2SecInfo

## Run the pipeline

On Windows, install Miniconda with winget if needed, create a local conda
environment, and install the dependencies:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
```

Then run the downloader, preprocessing, and asset discovery/classification:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run.ps1
```

The pipeline writes intermediate files to `processed\` and asset inventories to
`outputs\`. Use `powershell -ExecutionPolicy Bypass -File scripts\run.ps1 --skip-download`
to reuse existing data without accessing the mirror. Run
`powershell -ExecutionPolicy Bypass -File scripts\run.ps1 --help` for
input and output options.
Preprocessing accepts either the mirror's Parquet files or the original
TrafficLabelling CSV files, but not both in the same directory.

## CICIDS2017 dataset

Download the labeled network flows and machine-learning features (about 550 MB)
with Python 3:

```powershell
python scripts\download_cicids2017.py
```

The files are stored in `data\cicids2017` and ignored by Git. Run the same
command again to verify and reuse existing files. To also download the five raw
packet captures (about 52 GB), use:

```powershell
python scripts\download_cicids2017.py --pcap
```

The [public mirror](https://huggingface.co/datasets/bvsam/cic-ids-2017)
converts the original CSVs to Parquet and normalizes labeled-flow timestamps to
UTC. The captures are the original PCAPs. See the
[official dataset page](https://www.unb.ca/cic/datasets/ids-2017.html) for
dataset details and citation requirements.