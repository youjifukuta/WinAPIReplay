# NOTICE — Provenance of the sample identifiers

## What this directory contains

- `sample_manifest.csv` — 500 rows, one per analysed trace. Columns:
  `family` (family label), `sha256`, `source_file` (the WinMET volume and file
  the trace was taken from), `raw_event_count`, `converted_event_count`, `status`.
- `sample_selection/` — per-family selection lists (5 JSON files, 100 entries
  each). Entries carry the SHA-256 and, for most entries, the source path and
  event count.

## Origin

The SHA-256 values identify execution traces in the WinMET dataset.

The family labels are labels distributed with WinMET. For Redline, AgentTesla,
Amadey and Berbew they were taken from the AVClass-derived label index
(`avclass_report_to_label_mapping.json`); for Dacic, from the CAPE-detection
label index (`cape_report_to_label_mapping.json`), because Dacic is a
CAPEv2-specific label with no AVClass counterpart. WinMET also distributes a
consensus-label file (`reports_consensus_label.json`).

These 500 records are an extract of the WinMET dataset (31,844 traces),
selected as described in Section 4 of the accompanying paper.

## License

WinMET is distributed under the **GNU General Public License v3.0 or later**.

    Raducu, R., Villagrasa-Labrador, A., Rodríguez, R. J., & Álvarez, P. (2025).
    WinMET Dataset [Data set]. Zenodo.
    https://doi.org/10.5281/zenodo.12647555

**The authors of this repository make no license claim over the contents of
this directory.** The CC BY 4.0 license in `LICENSE-DATA` does not apply here.
Users who redistribute this material should observe the terms under which
WinMET itself is distributed.

No malware binaries are included. This directory contains only identifiers
and labels.
