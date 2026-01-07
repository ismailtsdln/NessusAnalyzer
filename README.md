# NessusAnalyzer 🧠

A modern vulnerability output parser and reporting toolkit. Designed for security professionals to quickly analyze Nessus results, prioritize exploitable vulnerabilities, and generate professional reports.

## 🚀 Overview

NessusAnalyzer simplifies the process of handling large Nessus scan files. It parses `.nessus` (XML) files, maps findings to internal models, and provides powerful filtering and reporting capabilities.

### Key Features
- **Smart Parsing**: Robust XML to Object mapping for `.nessus` files.
- **Exploit Focus**: Automatically highlights vulnerabilities with known exploits.
- **Multi-Format Export**: Generate reports in CSV, JSON, Excel (XLSX), and PDF.
- **Tuable/Nessus API**: Pull scans directly from your Tenable/Nessus instance.
- **Asset Grouping**: View vulnerabilities grouped by host or risk level.
- **Modular Design**: Easy to extend with new parsers or formatters.

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/ismailtsdln/NessusAnalyzer.git
cd NessusAnalyzer

# Install with pip
pip install .
```

## 🛠️ Usage

### CLI Examples

```bash
# Parse a file and show summary
nessusanalyzer parse scan_results.nessus

# Export findings to PDF
nessusanalyzer export --format pdf scan_results.nessus --output report.pdf

# Fetch latest scans from Tenable API
nessusanalyzer fetch --api-key <KEY> --secret-key <SECRET>
```

## 🧠 Core Architecture

- **Core**: Pydantic-based data models and XML parser.
- **Analyzer**: Risk scoring, exploit mapping, and business logic.
- **Formatter**: Pluggable export modules for various formats.
- **CLI**: Rich command-line interface powered by `click`.

## 🧪 Testing

```bash
pytest tests/
```

## 📜 License

This project is licensed under the MIT License.
