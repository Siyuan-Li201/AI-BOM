# Ai-Firmware
The code and dataset of the paper "AI-BOM for Firmware: Characterizing Models and Supply-Chain Risks in Edge AI Devices"


# Dataset
- The dataset lists are at "all_firmware_manifest.csv" and "firmware_count_summary.csv".
- The firmware can be download at: https://pan.baidu.com/s/1WbBUWysi_lrUZUik1OvWKg?pwd=azbi (Password: azbi)



# Analyze-tools
Static-analysis tools for identifying AI-related artifacts, model-component evidence, third-party components, and vulnerability candidates in firmware or firmware-like software packages.

## Contents

```text
01_ai_firmware_extract_profile.py
02_third_party_component_identify.py
03_nvd_vulnerability_match.py
model_profile_ext.py
run_ai_firmware_pipeline.py
analyze_ai_firmware_model_components.py
example_firmware.csv
requirements.txt
README.md
```

The repository provides two workflows:

1. **Full AI-firmware pipeline**
   Model extraction/profile -> third-party component inventory -> NVD vulnerability candidate matching.

2. **Standalone model-component analysis**
   High-level characterization of AI evidence, deployment type, model storage style, and usage style.

## Input CSV

Both workflows use a CSV file with at least:

```text
Model,Version,DownloadLink
```

Optional columns such as `Region` and `Date` are allowed.

Example:

```csv
Model,Version,Region,Date,DownloadLink
Autoware Universe,0.51.0,Global,2026-05-02,https://api.github.com/repos/autowarefoundation/autoware_universe/zipball/0.51.0
openpilot,v0.10.0,Global,2025-08-21,https://api.github.com/repos/commaai/openpilot/zipball/v0.10.0
```

## Environment

Python 3.8+ is recommended.

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Recommended system tools on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y git git-lfs unzip tar binutils file
```

Optional tools for closed firmware images:

```bash
sudo apt-get install -y binwalk p7zip-full squashfs-tools
```

`binwalk`, `7z`, and `unsquashfs` are only needed when using `--binwalk` or analyzing non-standard firmware images.

## Workflow 1: Full AI-Firmware Pipeline

Main runner:

```text
run_ai_firmware_pipeline.py
```

The pipeline has three stages:

```text
Stage 1: 01_ai_firmware_extract_profile.py
         Download/extract packages, identify AI model artifacts, profile parseable models,
         and collect raw SDK/runtime/library evidence.

Stage 2: 02_third_party_component_identify.py
         Build precise and broad third-party component inventories.

Stage 3: 03_nvd_vulnerability_match.py
         Match versioned components against local NVD CVE feeds.
```

`model_profile_ext.py` is used by Stage 1 for extended static model profiling, including ONNX, TensorFlow PB/PBTXT, PyTorch weights, NPZ, Keras H5, SafeTensors, CoreML, and OpenVINO XML.

### NVD Data

Stage 3 requires local NVD CVE JSON feeds. The `--nvd-dir` directory should contain files such as:

```text
nvdcve-2.0-2024.json.gz
nvdcve-2.0-2025.json.gz
nvdcve-2.0-2026.json.gz
```

The NVD database is not included in this repository.

### Run the Full Pipeline

```bash
mkdir -p demo_pipeline

/usr/bin/python3 run_ai_firmware_pipeline.py \
  -i example_firmware.csv \
  --work-dir demo_pipeline \
  --nvd-dir /path/to/nvd_feeds \
  --script-dir . \
  --python /usr/bin/python3 \
  --debug
```

Final outputs are written to:

```text
demo_pipeline/final_results/
```

Main output files:

```text
model_extraction_results.csv
distinct_model_files.csv
distinct_model_file_summary.csv
third_party_components_precise.csv
third_party_components_broad.csv
high_relevance_vulnerability_candidates.csv
```

### Common Pipeline Options

```bash
--redownload              Force re-download
--reextract               Force re-extraction
--binwalk                 Enable optional recursive firmware extraction
--retain-all-libs          Retain every discovered library in Stage 1
--max-samples 1            Analyze only the first input row
--cleanup-extracted-after  Delete extracted files after analysis
```

Do not use `--cleanup-extracted-after` if you want to inspect extracted files.

## Workflow 2: Standalone Model-Component Analysis

Main script:

```text
analyze_ai_firmware_model_components.py
```

This script performs high-level static characterization of AI/model evidence. It detects:

```text
standard model files       .tflite, .onnx, .pb, .pt, .h5
vendor/private formats     .rknn, .blob, .nnb, .xmodel, .dlc
optimized model artifacts  .engine, .trt, .xclbin, .so, .a, .ko, .elf, .bin
static/source-embedded model evidence
AI SDK/runtime keywords
local inference API calls
service or pipeline evidence
cloud-side AI endpoint evidence
```

It classifies each input item by:

```text
source_visibility
deployment
model_storage
usage
```

### Run Model-Component Analysis

```bash
mkdir -p demo_model_component_analysis

/usr/bin/python3 analyze_ai_firmware_model_components.py \
  -i example_firmware.csv \
  -o demo_model_component_analysis/ai_firmware_analysis.csv \
  --details demo_model_component_analysis/ai_firmware_analysis_details.csv \
  --download-dir demo_model_component_analysis/downloads \
  --extract-dir demo_model_component_analysis/extracted \
  --keep-files
```

Main outputs:

```text
ai_firmware_analysis.csv
ai_firmware_analysis_details.csv
ai_firmware_analysis_stats.csv
ai_firmware_analysis_stats_no_version.csv
```

### Common Model-Component Options

```bash
--redownload   Force re-download
--reextract    Force re-extraction
--keep-files   Keep downloaded and extracted files
--resume       Skip rows already present in the output CSV
--binwalk      Use optional firmware extraction tools
--no-stats     Disable statistics output
```

## Output Notes

`model_extraction_results.csv` records detected model artifacts, formats, hashes, retained paths, profile status, input/output shapes when available, operators, architecture guesses, and quantization hints.

`third_party_components_precise.csv` is the conservative component inventory used for vulnerability matching.

`third_party_components_broad.csv` keeps additional component review candidates.

`high_relevance_vulnerability_candidates.csv` contains NVD-based candidates. These are not confirmed exploitable vulnerabilities.

`ai_firmware_analysis_details.csv` contains detailed evidence for standalone model-component analysis, including model files, SDK keywords, inference API evidence, pipeline evidence, cloud evidence, and binary evidence.

## Important Notes

Vulnerability matches require manual validation. Vendor backports, build configuration, runtime reachability, and exposure should be checked before treating a CVE as exploitable.

Classification results are evidence-based labels and may require manual review, especially for weak binary strings, cloud URLs, and vendor-specific model formats.
