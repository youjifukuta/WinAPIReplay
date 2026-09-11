# WinAPIReplay — replication package

Re-execution tool, API signature database, conversion and evaluation scripts,
sample identifiers, and processed result files for the paper listed in section 1.

---

## 1. Overview

**Paper**

| | |
|---|---|
| Title | WinAPIReplay: Safely Re-Executing Win32 and NT-Native Malware API-Call Logs to Measure Behavioral Reproducibility and Generate Labeled Endpoint Telemetry |
| Authors | Youji Fukuta, Yoshiaki Shiraishi, Masanori Hirotomo, Masami Mohri |
| Journal | *Information* (MDPI), ISSN 2078-2489 |
| Manuscript ID | information-4532429 |
| DOI | *(to be added once assigned)* |

**What the tool does.** WinAPIReplay reads a recorded Windows API-call log and
re-executes each recorded Win32 and NT-native call as a real operating-system
call, **without the malware binary**. A unified handle map reconstructs handle
chains that cross the two API layers, and a three-tier sandbox (file path,
registry, network) confines every side effect to disposable places. The tool
consumes logs; it does not acquire them, and it never executes a malware sample.

**What this repository is.** It is the replication package for the paper: the
tool source, the signature database it reads, the scripts that convert and
evaluate logs and produce the paper's figures and tables, the SHA-256
identifiers of the 500 analysed traces, and the processed result files.
It does **not** contain the WinMET dataset (see section 7) and does **not**
contain the per-sample raw outputs (see section 9-9).

---

## 2. Contents

```
.
├─ README.md              this file
├─ LICENSE                MIT — applies to code and scripts
├─ LICENSE-DATA           CC BY 4.0 — applies to data/ and results/ (not to sample_identifiers/)
├─ THIRD-PARTY.md         bundled third-party components and their licences
├─ CITATION.cff           citation metadata
├─ requirements.txt       Python environment (full pip freeze)
├─ .gitignore
├─ CMakeLists.txt         build definition (CMake >= 3.20, C++17, MSVC)
├─ src/                   37 .cpp — tool implementation
│    ├─ replay/           14 core sources + executors/ (18 per-category executors)
│    └─ sample/           5 sources — WinAPISample, a scenario generator used in development
├─ include/               36 .h
├─ tests/                 26 .cpp — GoogleTest unit tests (471 tests)
├─ testdata/              3 .json — fixtures used by the unit tests
├─ external/
│    ├─ googletest/       GoogleTest 1.14.0 (BSD-3-Clause) — see THIRD-PARTY.md
│    └─ nlohmann/         nlohmann/json 3.11.3 single header (MIT) + LICENSE.MIT
├─ data/
│    └─ api_signatures.json    Layer-1 API signature database, 302 entries
├─ scripts/
│    ├─ python/           post-processing scripts (see section 6)
│    │    └─ collector/   dataset_converter.py, log_evaluator.py, sysmon_analyzer.py
│    └─ powershell/       experiment drivers (run_exp1 / run_exp0 / run_exp6 / run_determinism)
├─ sample_identifiers/    derived from WinMET — no licence claimed, see NOTICE.md
│    ├─ NOTICE.md                 provenance and licence status of this directory
│    ├─ sample_manifest.csv       500 rows: family, sha256, source_file, event counts, status
│    └─ sample_selection/         5 JSON files, 100 entries each (500 total)
└─ results/
     ├─ csv/              18 aggregated result files (CSV + sideeffect_raw.json)
     └─ figures/          12 files — 5 PNG figures and 7 XLSX tables
```

### `data/api_signatures.json`

A flat JSON object: one `_meta` block plus **302** API entries keyed by API name.
Each entry has `module`, `category`, `args`, `return_type`, `out_handle`,
`invalidates_arg`. Category breakdown: process 68, unknown 65, file 39, sync 37,
registry 34, network_winsock 13, dll 11, service 10, network_wininet 10,
crypto 8, shell 3, token 2, hook 2. Excluding `unknown` (the Layer-2 /
utility set) leaves 12 categories and 237 entries.

`NtUnmapViewOfSection` appears as a top-level key **twice** (once in the Win32
block and once in the NT-native block). JSON parsing keeps the later
definition; the two definitions are the reason the raw file contains 303 API
name strings for 302 distinct APIs. This is carried over from the version used
in the experiments and has not been changed.

### `sample_identifiers/`

`sample_manifest.csv` is the authoritative list of the 500 analysed traces:
`family, sha256, source_file, raw_event_count, converted_event_count, status`.
All 500 SHA-256 values are distinct. `source_file` records which WinMET volume
each trace came from.

`sample_selection/*.json` is the per-family selection produced by
`select_samples.py`, 100 entries per family. Four of the five files carry
`path`, `sha256`, `n_events`; `dacic_samples.json` carries an additional `stem`
field, and 7 of its 100 entries carry only `sha256` and `stem` because that
family's selection was rebuilt after a cross-family duplicate was removed.

---

## 3. Licence

| Part | Licence | File |
|---|---|---|
| Source code (`src/`, `include/`, `tests/`, `testdata/`, `CMakeLists.txt`, `scripts/`) | MIT | `LICENSE` |
| Data generated by the authors (`data/`, `results/`) | CC BY 4.0 | `LICENSE-DATA` |
| Sample identifiers (`sample_identifiers/`) | **No licence is claimed by the authors** — derived from WinMET (GNU GPL v3.0 or later) | `sample_identifiers/NOTICE.md` |
| Bundled third-party components (`external/`) | Their own licences (BSD-3-Clause, MIT) | `THIRD-PARTY.md` |

The SHA-256 identifiers and family labels in `sample_identifiers/` come from the
WinMET dataset, whose rights belong to the WinMET authors. This repository does
not license that material; anyone redistributing it should follow the terms under
which WinMET itself is distributed (section 7). The WinMET traces themselves are
**not** redistributed here.

---

## 4. Requirements

Verified on the machine that produced the results.

| Component | Version used |
|---|---|
| OS (host, build and post-processing) | Windows 11 Pro |
| OS (re-execution target) | Windows 10 Pro, in a Hyper-V virtual machine |
| C++ compiler | MSVC `cl.exe` 14.51.36231 (`_MSC_VER` reported as 19.51.36246.0) |
| Windows SDK | 10.0.26100.0 |
| CMake | 4.2.3-msvc3 (`CMakeLists.txt` requires >= 3.20) |
| Generator | Ninja |
| Architecture | x64 |
| C++ standard | C++17 |
| Python | CPython **3.14.5** (64-bit) |
| Python packages | see `requirements.txt` (full `pip freeze` of the environment the pipeline actually used) |
| Sysmon | System Monitor (Sysinternals) v15.21, installed in the virtual machine |

The tool links `Ws2_32`, `Wininet`, `Advapi32`, `Shell32`, `Shlwapi`,
`Pathcch`, `Ole32`, `Psapi`. `Ntdll` is deliberately **not** linked;
`NtUnmapViewOfSection` is resolved at run time through `GetProcAddress`.

The only external code dependencies are the two bundled libraries in
`external/`. There is no package manager manifest (no vcpkg, no Conan) and none
is needed.

---

## 5. Build

These are the exact commands that were run to verify this tree. They were
executed on a fresh copy of this repository, in a directory containing no
previous build output.

```bat
:: 1. Set up the MSVC x64 environment
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"

:: 2. Configure (out-of-source, Ninja, Release)
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release

:: 3. Build all three targets
cmake --build build
```

Result of the verification run: **101/101 build steps succeeded, exit code 0.**
Three executables are produced in `build\`:

| Target | Purpose |
|---|---|
| `WinAPIReplay.exe` | the re-execution tool |
| `WinAPIReplayTests.exe` | the GoogleTest unit tests |
| `WinAPISample.exe` | scenario generator used during development |

The build emits warnings (`C4005` for `WIN32_LEAN_AND_MEAN` / `NOMINMAX` being
redefined, and `C4995` for deprecated `PathCombineW` / `PathAppendW` /
`PathCanonicalizeW` / `PathAddBackslashW`, which the tool calls deliberately
because the logs contain those calls). No errors.

### Unit tests

```bat
build\WinAPIReplayTests.exe
```

Result of the verification run:

```
[==========] 471 tests from 35 test suites ran. (286 ms total)
[  PASSED  ] 471 tests.
```

Exit code 0. The tests must be run with the repository root as the working
directory, because `testdata\` is referenced by relative path
(`CMakeLists.txt` sets `gtest_discover_tests(... WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})`
for the same reason).

**The unit tests touch the real file system and registry of the machine they run
on.** Several tests use fixed absolute paths under `C:\tmp\` (for example
`C:\tmp\FETest`, `C:\tmp\NtFileTest`) and registry keys under
`HKCU\Software\` (for example `RETest`, `WARChainTest`, and the registry sandbox
root `WinAPIReplaySandbox`). Most of this is removed again by the tests, but not
all of it: in the verification run, `GetTempFileNameW_CreatesUniqueFile` left one
empty `C:\tmp\FETest\FET*.tmp` file behind, and keys `HKCU\Software\RETest` and
`HKCU\Software\WARChainTest` left by earlier runs were still present. Run the
tests on a machine or account where that is acceptable.

`ctest -C Release` from `build\` is an alternative runner
(`gtest_discover_tests` registers every test individually).

### Python scripts

```bat
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

**No Python unit tests are included.** The development tree had pytest tests
for some of the scripts, but they were written against the development
directory layout and do not run in this repository's layout; see 9-12.

---

## 6. Running the pipeline

The full pipeline has five stages. Stages 2 and 4 run **inside an isolated
virtual machine**; stages 1, 3 and 5 run on the host.

```
 (1) select_samples.py            WinMET volumes  ->  sample_manifest.csv, input\<family>\*.json
     batch_convert.py             per-family selection lists -> one dataset_converter.py run per sample
       └─ collector\dataset_converter.py   one WinMET trace -> one re-execution input JSON
                                           (see "Converting the traces" below: 7 Dacic entries need manual handling)

 (2) WinAPIReplay.exe             input JSON      ->  <sha>_result.json        [in the VM]

 (3) collector\log_evaluator.py   input + result  ->  <sha>_eval.json

 (4) collector\sysmon_analyzer.py Sysmon EVTX + result-json transforms
                                                  ->  <sha>_sysmon.json, exp6_sysmon.csv

 (5) generate_reports.py          eval + replay + sideeffect_raw.json + exp3_timing_raw.csv
                                                  ->  exp1_detail.csv, exp1_summary.csv,
                                                      exp2_*.csv, exp4_*.csv
     generate_exp3.py             exp3_timing_raw.csv -> exp3_timing.csv, fig_exp3_scatter.png
     generate_figures.py          exp1_*.csv      ->  fig_exp1_family.png, fig_exp1_category.png
     exp0_ablation_analyzer.py    eval + eval_baseline -> exp0_ablation.csv
     exp5_failure_analyzer.py     eval            ->  exp5_failure.csv
     exp1_determinism_check.py    det_run1..3     ->  exp1_determinism.csv
     exp7_classifier_v2.py        exp6_sysmon.csv + eval -> exp7_classifier_v2.csv,
                                                      exp7_per_family_v2.csv,
                                                      fig_exp7_v2_confusion.png
     generate_tables_and_draft.py all CSV         ->  table_exp*.xlsx, fig_exp6_sysmon.png
```

### Converting the traces (stage 1)

`batch_convert.py` reads the per-family selection lists — shipped here as
`sample_identifiers/sample_selection/*_samples.json`; the script itself points at
`C:\tmp\sample_selection` (see section 10) — and runs
`collector/dataset_converter.py` once per sample:

```
python dataset_converter.py <WinMET trace> --output <input\<Family>\<sha256>.json> --process main
```

It takes the WinMET trace to convert from each entry's `"path"` field.
**Seven of the 100 Dacic entries carry no `"path"` field.** They are the
last seven entries of `dacic_samples.json`, and they were substituted at a
later stage of the selection process, when seven cross-family duplicates were
replaced. `batch_convert.py` reads `"path"` before it checks whether a sample
has already been converted, so it **stops with `KeyError: 'path'` on the first
of these seven entries**, after converting the 400 samples of the other four
families and the first 93 Dacic samples.

The source path of **all 500** traces is recorded in the `source_file` column of
`sample_identifiers/sample_manifest.csv`. Use that column to convert the seven
remaining Dacic entries with the command above — or use it instead of the
selection lists to drive the whole conversion. `batch_convert.py` is shipped
unchanged, as it was used; see 9-13.

### The tool

```bat
WinAPIReplay.exe <input.json> ^
  --signatures data\api_signatures.json ^
  --sandbox C:\Sandbox --sandbox-registry --net-sim ^
  --single-thread --no-spawn ^
  --result-json <out.json>
```

Variants used in the paper: `--dry-run` (Experiment 3, overhead measurement)
and `--no-l1-executor` (Experiment 0, ablation baseline).

### The experiment drivers

`scripts\powershell\` contains the four drivers that ran the campaigns:

| Script | Experiment |
|---|---|
| `run_exp1.ps1` | Experiments 1–3, all 500 samples. Also writes `exp3_timing_raw.csv` and `sideeffect_raw.json` |
| `run_exp0.ps1` | Experiment 0, ablation, first 20 samples per family |
| `run_exp6.ps1` | Experiment 6, Sysmon telemetry, first 20 samples per family |
| `run_determinism.ps1` | RQ7 determinism, first 4 samples per family, 3 runs each |

They drive the virtual machine over PowerShell Direct
(`New-PSSession -VMName ... -Credential ...`).

**VM credentials.** The scripts read the credential from a path given in the
environment variable `WINAPIREPLAY_VM_CRED`. Create the file yourself with
`Export-Clixml`; it is encrypted by Windows DPAPI and can only be decrypted by
the same user on the same machine, so it is neither included here nor portable.

```powershell
# once, on the host, as the account that will run the pipeline
Get-Credential | Export-Clixml "$env:USERPROFILE\winapireplay-vm-cred.xml"
$env:WINAPIREPLAY_VM_CRED = "$env:USERPROFILE\winapireplay-vm-cred.xml"
```

If the variable is unset, or points at a file that does not exist, the scripts
stop with an explanatory error.

---

## 7. Dataset

The input traces come from the **WinMET dataset**, which is **not**
redistributed in this repository.

| | |
|---|---|
| DOI | [10.5281/zenodo.12647555](https://doi.org/10.5281/zenodo.12647555) — the concept DOI, which always resolves to the latest version |
| Contents | 31,844 Windows malware execution traces recorded with the CAPEv2 sandbox, in 5 volumes |
| Size | About 13 GB as five 7z archives; about 750 GB once extracted (figure from the dataset's own description) |
| **Licence** | **GNU General Public License v3.0 or later** |
| Archive password | The 7z archives are password-protected. **The password is published by the dataset itself, in the description on its Zenodo record** — take it from there, not from this repository. |

Cite the dataset as:

    Raducu, R., Villagrasa-Labrador, A., Rodríguez, R. J., & Álvarez, P. (2025).
    WinMET Dataset [Data set]. Zenodo.
    https://doi.org/10.5281/zenodo.12647555

Obtain the dataset from the DOI above and observe its licence. The identifiers
and family labels in `sample_identifiers/` are an extract of it; see
`sample_identifiers/NOTICE.md`.

The experiments expect the extracted volumes at
`D:\WinMET\WinMET_volume_1` … `WinMET_volume_5`. `select_samples.py` also reads
the two label-mapping files distributed with the dataset
(`avclass_report_to_label_mapping.json`, `cape_report_to_label_mapping.json`).

**Sample selection.** Five families (Redline, AgentTesla, Amadey, Berbew by
`avclass_detection`; Dacic by `cape_detection`), up to 100 samples each, taking
the dataset's own listing order, excluding traces with fewer than 50 API calls
and excluding duplicate SHA-256 values. The resulting 500 traces are listed in
`sample_identifiers/sample_manifest.csv`.

---

## 8. Provenance of the paper's figures and tables

Each numbered Table and Figure of the paper, the file in this repository that
backs it, and the script that produced that file.

| Paper | Label | Backing file in this repository | Produced by |
|---|---|---|---|
| Table 1 | `tab:related` | — (literature comparison; no data file) | — |
| Table 2 | `tab:dataset` | `sample_identifiers/sample_manifest.csv`, `sample_identifiers/sample_selection/*.json`, `results/csv/exp1_summary.csv` (the per-family recorded-event counts and the total 2,333,242) | `select_samples.py`; `generate_reports.py` |
| Table 3 | `tab:expmap` | — (experiment-to-research-question map; no data file) | — |
| Table 4 | `tab:metrics` | — (metric definitions; no data file) | — |
| Table 5 | `tab:bias` | **not included — see 9-1** | **not included — see 9-1** |
| Table 6 | `tab:exp0` | `results/csv/exp0_ablation.csv` → `results/figures/table_exp0.xlsx` | `exp0_ablation_analyzer.py` → `generate_tables_and_draft.py` |
| Table 7 | `tab:substitute` | **not included — see 9-1** | **not included — see 9-1** |
| Table 8 | `tab:exp1family` | `results/csv/exp1_summary.csv`, `results/csv/exp1_detail.csv` → `results/figures/table_exp1.xlsx` | `generate_reports.py` → `generate_tables_and_draft.py` |
| Table 9 | `tab:exp5` | `results/csv/exp5_failure.csv` | `exp5_failure_analyzer.py` |
| Table 10 | `tab:safety` | `results/csv/exp2_file.csv`, `exp2_registry.csv`, `exp2_network.csv`, `results/csv/sideeffect_raw.json` → `results/figures/table_exp2.xlsx`. **These back the "escapes" and "background" columns. For the "intercepted and redirected" column see 9-10.** | `run_exp1.ps1` → `generate_reports.py` → `generate_tables_and_draft.py` |
| Table 11 | `tab:exp6` | `results/csv/exp6_sysmon.csv` → `results/figures/table_exp6.xlsx` | `collector/sysmon_analyzer.py` → `generate_tables_and_draft.py` |
| Table 12 | `tab:exp7` | `results/csv/exp7_classifier_v2.csv`, `exp7_per_family_v2.csv` → `results/figures/table_exp7_v2.xlsx` | `exp7_classifier_v2.py` |
| Figure 1 | `fig:arch` | **not included — see 9-2** | — |
| Figure 2 | `fig:handlechain` | **not included — see 9-2** | — |
| Figure 3 | `fig:outcome` | **not included — see 9-2** | — |
| Figure 4 | `fig:environment` | **not included — see 9-2** | — |
| Figure 5 | `fig:exp1family` | `results/figures/fig_exp1_family.png` ← `results/csv/exp1_summary.csv` | `generate_figures.py` |
| Figure 6 | `fig:exp1category` | `results/figures/fig_exp1_category.png` ← `results/csv/exp1_detail.csv` | `generate_figures.py` |
| Figure 7 | `fig:exp3` | `results/figures/fig_exp3_scatter.png` ← `results/csv/exp3_timing.csv` ← `results/csv/exp3_timing_raw.csv` | `generate_exp3.py` (raw file written by `run_exp1.ps1`) |
| Figure 8 | `fig:exp7` | `results/figures/fig_exp7_v2_confusion.png` | `exp7_classifier_v2.py` |

Supporting text, not a numbered Table or Figure:

| Claim in the paper | Backing file | Produced by |
|---|---|---|
| Near-determinism, 98.90% stable (62,507 events compared, 685 non-deterministic) | `results/csv/exp1_determinism.csv` | `run_determinism.ps1` → `exp1_determinism_check.py` |
| Per-family API-category behaviour, top APIs, side-effect operation counts | `results/csv/exp4_family.csv`, `exp4_top_apis.csv`, `exp4_sideeffect.csv` → `results/figures/table_exp4.xlsx` | `generate_reports.py` → `generate_tables_and_draft.py` |
| Execution-cost distribution and dry-run overhead | `results/csv/exp3_timing.csv` → `results/figures/table_exp3.xlsx` | `generate_exp3.py` / `generate_tables_and_draft.py` |
| Sysmon event counts per family | `results/figures/fig_exp6_sysmon.png` | `generate_tables_and_draft.py` |

`results/figures/table_exp3.xlsx`, `table_exp4.xlsx` and `fig_exp6_sysmon.png`
do **not** correspond to a numbered Table or Figure of the paper. They are the
outputs of the same scripts and are included because they are the tabular form
of `results/csv/exp3_*`, `exp4_*` and `exp6_sysmon.csv`.

### Reproducing the headline number

The primary metric, the Layer-1 Behavior Reproduction Rate, is recomputed from
the per-sample evaluation outputs by `generate_reports.py`:

```
L1_total   = success + failed + approx - layer2_executed          (per sample, from the eval JSON)
L1_success = sum of by_category[].success for every category except 'unknown'
L1 BRR     = L1_success / L1_total
```

Aggregated over the 500 samples this gives

```
total recorded events  2,333,242
skipped                   15,151
layer2_executed          939,105
L1_total               1,352,778
L1_success             1,001,634
L1 BRR                    74.0427%   -> 74.04%
L1 coverage               57.98%
```

which are the values reported in the paper. `results/csv/exp1_summary.csv`
carries the same figures per family and in the `OVERALL` row.

---

## 9. Known limits on reproduction

These are stated as facts. Nothing here is worked around or hidden.

**9-1. The scripts that produced Table 5 and Table 7 are not in this
repository.** Table 5 (`tab:bias`, the four measurement biases, including the
89,877 calls bounded at +6.64 percentage points) and Table 7
(`tab:substitute`, the 39,177 substituted calls) report counts that no script
in the development tree computes. A search of all 150 Python and PowerShell
files in the development environment for the strings `39177`, `89877`,
`71.15`, `6.64` and `substitute` returned zero matches. The numbers were
derived by a one-off analysis whose code was not kept. The same applies to the
per-channel counts quoted in the Limitations section (named kernel objects,
process/thread/shell launches, service-control calls, Winsock calls,
block-listed terminations, COM activations, device-control requests).

**9-2. Figures 1–4 are schematic.** `fig:arch`, `fig:handlechain`,
`fig:outcome` and `fig:environment` are architecture and procedure diagrams
drawn for the paper. They have no backing data file, and their source artwork
is not part of this repository.

**9-3. The 95% bootstrap confidence intervals cannot be reproduced from this
repository.** The intervals reported for the Layer-1 Behavior Reproduction Rate
(`[71.02, 76.75]` for 74.04%, `[68.15, 73.88]` for the conservative 71.15%) were
computed by sample-level stratified bootstrap with 10,000 replicates. No script
here performs a bootstrap — the strings `bootstrap`, `resample` and `replicate`
do not appear in any script — and **the random seed was not recorded.** The
Wilson intervals reported alongside them *are* reproducible: `wilson_ci()` in
`generate_reports.py` and in `exp7_classifier_v2.py` computes them
deterministically.

**9-4. `exp7_classifier_v2.py` is deterministic.** It sets `RANDOM_STATE = 42`
(line 78) and passes it to the random forest and to `StratifiedKFold`. The
per-fold vocabulary construction iterates over `sorted(...)` sets (lines 266 and
268), so the leave-one-out accuracies, the McNemar statistic and the confusion
matrices are reproducible. This determinisation was applied after the first
run; see 9-7 for the one remaining source of variation.

**9-5. `exp4_top_apis.csv` has a tie that depends on file enumeration order.**
For the Berbew family four APIs have exactly the same call count and compete
for three ranked places. `generate_reports.py` line 466 enumerates input files
with `glob.glob(...)` **without** `sorted(...)`, and the counts feed
`Counter.most_common(10)` at line 488, whose tie-break follows insertion order.
On another filesystem the ranking among the tied APIs may differ. The counts
themselves are unaffected.

**9-6. `generate_tables_and_draft.py` line 126 has the same pattern.** It also
enumerates with an unsorted `glob.glob(...)`. Its aggregation is addition only,
so the totals do not depend on order, but the enumeration-order dependency is
present in the code.

**9-7. `PYTHONHASHSEED` is not fixed.** With the determinisation of 9-4 the
primary results (`BC_T_combined`, `D_api_categories`) are stable, but the
auxiliary feature set `BCE_T_combined` can vary by about one sample
(±1.0 percentage point) in its 5-fold accuracy across interpreter runs.
**To reproduce the published values exactly, set `PYTHONHASHSEED=0` before
running `exp7_classifier_v2.py`.**

**9-8. `data/api_signatures.json` in this repository differs from the file used
in the experiments by one field.** The experiments ran with
`_meta.total = 104`, a stale value left over from an earlier version of the
database; the file has contained 302 entries since well before the campaign.
In this repository that field has been corrected to `302`. This changes nothing
about behaviour: the tool skips the `_meta` block entirely when it loads the
database (`src/replay/arg_preparer.cpp`, `SignatureDB::Load`, line 33:
`if (it.key() == "_meta") continue;`). Both hashes are recorded so the change
is auditable:

| | SHA-256 |
|---|---|
| As used in the experiments (`_meta.total = 104`) | `d267470c742c9b93cbd5f6d2a08935722f4f766abf03931a7da46abe15c89542` |
| In this repository (`_meta.total = 302`) | `07c4b61e11140c56f4e0c5d1ea4d59565c46b215a5c0c799c019f6969ee5f4d3` |

The files are otherwise byte-identical (both 77,182 bytes).

**9-9. The per-sample raw outputs are not included.** The re-execution campaign
produced about 1,920 MB of per-sample JSON and EVTX files (500 evaluation
outputs, 500 replay results, 79 ablation pairs, 100 Sysmon captures, three
20-sample determinism runs). They are excluded because they carry the
security identifier (SID) of the virtual machine's user account and absolute
paths under that account. Consequently the aggregation scripts in
`scripts/python/` cannot be re-run end to end against this repository alone —
they need the raw outputs, which stage 2 of section 6 regenerates. Section 8
maps each Table and Figure to its backing file and states where no such file
exists.

**9-10. One column of Table 10 could not be traced to a file in this
repository.** The "intercepted and redirected" counts of Table 10
(file 122,841; registry 462,839; network 65) do not match any aggregated file
here. The closest values are the per-category totals in
`results/figures/table_exp1.xlsx` (file 125,531; registry 465,708;
network_winsock 69), which are larger. The escape counts (0 in all three
channels) and the background-activity counts (23 file operations, 0 registry,
645 non-loopback connections) **are** reproduced exactly by
`results/csv/exp2_*.csv` and `results/csv/sideeffect_raw.json`. The origin of
the first column could not be determined from the material in this repository.

**9-11. Two API categories in the signature database are never exercised by
this corpus.** `network_wininet` (10 entries) and `token` (2 entries) are
implemented and present in `data/api_signatures.json`, but no call of either
category occurs in the 500 traces, so no measured rate is reported for them.

**9-12. The Python post-processing scripts ship without unit tests.** The
development tree contained pytest tests for `generate_*.py`, `dataset_converter.py`
and `log_evaluator.py`. When run in this repository's layout they did not pass
(49 passed, 4 failed, 2 could not be collected): two test modules cannot import
the scripts they test once those scripts live in `scripts/python/collector/`, two
tests expect a legacy module that is not part of this repository, and two tests
in `test_generate_reports.py` fail (`KeyError: 'violations'`; a `ValueError`
raised inside `wilson_ci` for a negative input). Rather than ship tests that do
not pass, they have been left out. The C++ unit tests (471, all passing) are
included; see section 5.

**9-13. `batch_convert.py` cannot convert all 500 samples on its own.** It
takes each trace's location from the `"path"` field of the selection lists in
`sample_identifiers/sample_selection/`, but 7 of the 100 Dacic entries — the
seven substitutes added when cross-family duplicates were replaced — have no
such field, and the script stops with `KeyError: 'path'` at the first of them.
In the original campaign those seven traces were converted by a separate step
that is not part of this repository, invoking `dataset_converter.py` with the
same arguments. The `source_file` column of
`sample_identifiers/sample_manifest.csv` gives the source path for all 500
traces, including these seven; see "Converting the traces" in section 6. The
script is shipped as it was used and has not been modified.

---

## 10. About the absolute paths in this repository

The scripts contain absolute paths from the development machine:

| Path | What it was |
|---|---|
| `C:\Projects\Experiments\` | working directory for inputs, results and reports |
| `C:\Projects\WinAPIReplay\` | tool source tree |
| `C:\Projects\WinAPICollector\` | converter / evaluator / Sysmon analyser, and the Python virtual environment |
| `C:\tmp\` | experiment drivers and the sample-selection output |
| `D:\WinMET\` | extracted WinMET volumes |
| `C:\Users\WinAPITest\Desktop\` | tool and working directory **inside the virtual machine** |
| `C:\Sandbox` | file-sandbox root inside the virtual machine (the design described in the paper) |

**These are recorded deliberately.** They document the environment the reported
numbers came from, and the drivers are unreadable without them. A third party
must read them as their own paths. The registry sandbox root
`HKCU\Software\WinAPIReplaySandbox` and the VM account name `WinAPITest` are
likewise part of the documented experimental setup, not accidental leftovers.

The only value that was removed is the path of the VM credential file, which is
now supplied through `WINAPIREPLAY_VM_CRED` (section 6).

---

## 11. How to cite

Cite the paper (section 1). `CITATION.cff` carries machine-readable metadata for
both the software and the paper; the DOI fields are filled in once the DOI is
assigned. If you use the dataset, cite WinMET separately (section 7).
