# Third-party components

This repository bundles the following third-party code components in `external/`,
and derives its sample identifiers from one third-party dataset. None of these is
covered by this repository's `LICENSE` (MIT) or `LICENSE-DATA` (CC BY 4.0); each
retains its own licence.

| Component | Version | Licence | Location / notes |
|---|---|---|---|
| GoogleTest | 1.14.0 | BSD-3-Clause | `external/googletest/LICENSE` |
| nlohmann/json | 3.11.3 | MIT | `external/nlohmann/LICENSE.MIT` |
| WinMET Dataset | v3 (2025-07-25) | **GNU GPL v3.0 or later** | **Not bundled in this repository.** Only the identifiers and family labels in `sample_identifiers/` derive from it; see `sample_identifiers/NOTICE.md` |

## GoogleTest 1.14.0

* Upstream: https://github.com/google/googletest
* Copyright 2008, Google Inc. All rights reserved.
* Licence: BSD 3-Clause. Full text: `external/googletest/LICENSE` (28 lines,
  copied unmodified from the upstream distribution).
* Bundled because `CMakeLists.txt` calls `add_subdirectory(external/googletest)`
  to build the unit-test target `WinAPIReplayTests`.
* Version determined from `external/googletest/CMakeLists.txt`
  (`set(GOOGLETEST_VERSION 1.14.0)`).
* The upstream archive `googletest-1.14.0.zip` that was present in the
  development tree is **not** included here; only the extracted source is.

## nlohmann/json 3.11.3

* Upstream: https://github.com/nlohmann/json
* Copyright: `SPDX-FileCopyrightText: 2013-2023 Niels Lohmann <https://nlohmann.me>`
* Licence: MIT (`SPDX-License-Identifier: MIT`). Full text:
  `external/nlohmann/LICENSE.MIT`.
* Bundled as the single header `external/nlohmann/json.hpp`, included by the
  tool as `#include <nlohmann/json.hpp>`.
* Version determined from the header itself
  (`NLOHMANN_JSON_VERSION_MAJOR 3` / `MINOR 11` / `PATCH 3`).
* **Note on provenance:** the upstream distribution ships a `LICENSE.MIT` file
  alongside the header. That file was not present in the development tree, so
  `external/nlohmann/LICENSE.MIT` in this repository was reconstructed from the
  standard MIT licence text using the copyright line carried in the header of
  `json.hpp` itself.

## WinMET Dataset v3 (2025-07-25)

* Record: https://doi.org/10.5281/zenodo.12647555 (concept DOI; resolves to the latest version)
* Licence: **GNU General Public License v3.0 or later**
* Citation: Raducu, R., Villagrasa-Labrador, A., Rodríguez, R. J., & Álvarez, P. (2025).
  WinMET Dataset [Data set]. Zenodo. https://doi.org/10.5281/zenodo.12647555
* **Not redistributed here.** No trace, report or malware binary from WinMET is
  included. The SHA-256 identifiers and family labels in `sample_identifiers/`
  are an extract of WinMET; the authors of this repository make no licence claim
  over them. See `sample_identifiers/NOTICE.md`.

## Not bundled

The following are required to build or run but are **not** redistributed here:

| Component | Role | Where to obtain |
|---|---|---|
| Microsoft Visual C++ (MSVC) toolset and Windows SDK | Compiler / platform headers and import libraries | Visual Studio installer |
| CMake, Ninja | Build system | https://cmake.org / https://ninja-build.org |
| Python packages (numpy, pandas, scikit-learn, scipy, matplotlib, seaborn, openpyxl, pytest, …) | Post-processing scripts | `requirements.txt` |
| Sysmon (System Monitor, Windows Sysinternals) v15.21 | Telemetry generation in the virtual machine | https://learn.microsoft.com/sysinternals/downloads/sysmon |
| WinMET dataset (GNU GPL v3.0 or later) | Input traces | https://doi.org/10.5281/zenodo.12647555 (see `README.md` section 7 and `sample_identifiers/NOTICE.md`) |
