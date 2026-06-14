# MARS Static

MARS Static is a Python-based Malware Analysis & Reverse-engineering System focused on safe static inspection of Windows executables and archives. It provides a CustomTkinter desktop interface, a modular analysis pipeline, YARA rule matching, package unpacking, PE metadata extraction, and JSON/PDF report generation.

> Safety note: this project is intended for defensive analysis in an isolated lab environment. Do not run unknown samples on a production or personal machine.

## Features

- Desktop GUI for selecting samples and viewing analysis results.
- Intake validation for file existence, size limits, allowed extensions, hashes, magic bytes, and metadata.
- Archive/package handling for ZIP/MSI-style inputs with recursive ZIP extraction depth limits.
- Extracted-file inventory with SHA256 hashes and flagged payload extensions.
- PE static analysis using `pefile`.
- Security mitigation checks including DEP/NX, ASLR, CFG, SafeSEH, stack canaries, CET/shadow stack, force integrity, and AppContainer.
- Section entropy and permission checks for packing and suspicious RWE sections.
- Suspicious import detection for process injection, execution, network, and anti-analysis APIs.
- Manifest parsing for requested execution level.
- Regex-based artifact extraction for IPs, URLs, registry paths, emails, and password-like strings.
- Local YARA scanning with rules from `rules/rules.yar`.
- JSON and PDF report output under `workspace/reports`.

## Project Structure

```text
MARS_Static/
|-- config/
|   `-- config.yaml          # Pipeline, workspace, GUI, and static-analysis settings
|-- core/
|   |-- intake.py            # File validation, hashing, metadata extraction
|   |-- package.py           # Archive extraction and extracted-file inventory
|   |-- pipeline.py          # Analysis orchestration and GUI event wiring
|   |-- report.py            # JSON and PDF report generation
|   `-- static.py            # PE parsing, strings, imports, mitigations, YARA
|-- gui/
|   `-- app.py               # CustomTkinter desktop dashboard
|-- rules/
|   `-- rules.yar            # Local YARA ruleset
|-- workspace/
|   |-- extracted/           # Extracted archives and inventory logs
|   `-- reports/             # Generated JSON/PDF reports
|-- main.py                  # Application entry point
|-- requirements.txt         # Python dependencies
`-- README.md
```

## Requirements

- Python 3.10 or newer recommended
- Windows recommended for GUI use and PE sample workflows
- `pip`

Python packages are listed in `requirements.txt`:

```text
PyPubSub
PyYAML
pefile
yara-python
fpdf2
customtkinter
```

## Setup

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

If `yara-python` fails to install, make sure your Python version and build tools are compatible with the wheel available for your platform.

## Running the Application

Start the GUI:

```powershell
python main.py
```

The application will:

1. Verify required workspace directories.
2. Load `config/config.yaml`.
3. Compile YARA rules from `rules/rules.yar`.
4. Open the MARS desktop interface.

Use **Browse** to select a supported file, then click **Start Analysis**.

## Supported Input Types

The default configuration allows:

- `.zip`
- `.exe`
- `.dll`
- `.msi`
- `.sys`

You can adjust this list in `config/config.yaml` under:

```yaml
system:
  allowed_extensions:
```

## Output

Each successful analysis gets a unique ID like:

```text
MARS-YYYYMMDDHHMMSS-XXXXXX
```

Generated files are written to:

```text
workspace/reports/
```

Typical report names:

```text
MARS-20260614204701-CA5A93_Report.json
MARS-20260614204701-CA5A93_Report.pdf
```

Archive inventory logs and extracted contents are written to:

```text
workspace/extracted/
```

## Configuration

Main settings live in `config/config.yaml`.

Important options:

- `system.max_file_size_gb`: maximum input file size.
- `system.allowed_extensions`: accepted sample extensions.
- `system.max_unpack_depth`: recursive archive unpacking depth limit.
- `system.workspace_dir`: workspace root.
- `system.extract_dir`: extracted-file output directory.
- `system.reports_dir`: report output directory.
- `static_analysis.yara_rules_path`: YARA rules file path.
- `static_analysis.entropy_threshold`: entropy threshold for packed/obfuscated sections.
- `static_analysis.suspicious_imports`: API names to flag during import analysis.

## Analysis Flow

```text
File selected in GUI
        |
        v
Intake validation and hashing
        |
        v
Package extraction if archive input
        |
        v
Static PE analysis for executable inputs or extracted payloads
        |
        v
JSON and PDF report generation
```

## Notes

- Static analysis does not execute the target file.
- ZIP extraction includes basic protection against absolute paths and parent-directory traversal.
- YARA scanning is skipped if the rules file cannot be compiled.
- Non-PE files inside archives are inventoried but not passed through PE static analysis.

## Recommended Lab Practices

- Use a disposable VM or isolated malware-analysis workstation.
- Keep samples in a dedicated directory outside normal user documents.
- Do not double-click or execute analyzed files.
- Disable shared clipboards/folders when analyzing live malware.
- Treat generated extracted files as potentially malicious.
