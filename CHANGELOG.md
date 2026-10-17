# Changelog

## [0.2.0] - 2026-10-17

### Added

- Explicit `--python` selection, activated-environment detection, and target
  interpreter identification in every report.
- Explicit `--project` audits, including project extras and dependency groups.
- Direct and transitive dependency graphs evaluated against the target
  interpreter's Python version and platform.
- Diagnostics for missing packages, incompatible versions, and failed funding
  lookups; `--strict` makes an incomplete report fail.
- Deterministic text, Markdown, and versioned JSON reports.
- Guarded browser opening for a single funding destination.

### Changed

- Preserve environment scanning as the default. Recognized isolated tool
  environments require activation or an explicit target.
- Replace `--json` and `--markdown` with `--format`; revise the JSON structure
  and Python API.
- Include dependencies when inspecting named packages.
- Add GitHub funding links even when installed metadata already declares
  funding, and preserve meaningful URL parameters when grouping destinations.
- Move the package into `src/` and adopt shared testing, documentation, and
  release workflows.

[0.2.0]: https://github.com/recite/pip-fund/compare/a9bda4f...8a24448bbd4b3e6f75782dcf1414fe67c1073a53
