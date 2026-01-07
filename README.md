# NessusAnalyzer 🧠

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A high-performance, professional vulnerability output parser and reporting toolkit. **NessusAnalyzer** is designed for security engineers and researchers to transform raw Nessus scan data into actionable intelligence through advanced filtering, risk scoring, and multi-format reporting.

---

## ✨ Key Features

- **🚀 Advanced Parsing**: Lightning-fast XML parsing of `.nessus` files into structured Python objects using `lxml` and `Pydantic`.
- **🛡️ Exploit Mapping**: Automatically identify and isolate vulnerabilities with known Metasploit modules or available exploits.
- **📊 Rich Analytics**: Comprehensive risk summaries with breakdown by severity (Critical, High, Medium, Low, Info).
- **📋 Multi-Format Export**: Generate professional reports in:
  - **PDF**: Executive-ready summaries with color-coded severity.
  - **Excel (XLSX)**: Styled spreadsheets for easy audit tracking.
  - **CSV**: Clean data for external tool ingestion.
  - **JSON**: Fully serialized schema for automation pipelines.
- **🎨 Modern CLI**: A beautiful, colorized terminal interface powered by `rich` and `click`.
- **🔌 Tenable Integration**: (Skeletal) Support for fetching scans directly via Tenable.io API.

---

## 📦 Installation

### Prerequisites
- Python 3.10 or higher
- `pip` (Python package manager)

### Quick Start
```bash
# Clone the repository
git clone https://github.com/ismailtsdln/NessusAnalyzer.git
cd NessusAnalyzer

# Install dependencies and the package
pip install .
```

---

## 🛠️ Usage

NessusAnalyzer provides a powerful CLI with intuitive subcommands.

### 📝 Parse & Summary

Quickly analyze a scan file and see the risk distribution:

```bash
nessusanalyzer parse scan_results.nessus --summary
```

### 🎯 Identify Exploitable Risks

List only the vulnerabilities that have publicly known exploits:

```bash
nessusanalyzer exploitable scan_results.nessus
```

### 📄 Exporting Reports

Export your findings to your preferred format:

```bash
# Generate a professional PDF report
nessusanalyzer export scan_results.nessus --format pdf -o internal_audit.pdf

# Export to a styled Excel sheet
nessusanalyzer export scan_results.nessus --format xlsx -o tracking_sheet.xlsx
```

---

## 🏗️ Architecture

The project follows a modular, layer-based architecture for maximum extensibility:

- `nessusanalyzer.core`: Data models and core XML parsing logic.
- `nessusanalyzer.analyzer`: Business logic for risk scoring and exploit prioritization.
- `nessusanalyzer.formatter`: Pluggable reporting modules for various file formats.
- `nessusanalyzer.cli`: User interface layer with rich terminal feedback.
- `nessusanalyzer.api`: External service integrations (Tenable/Nessus).

---

## 🧪 Testing

We maintain high standards for code quality. You can run the test suite using `pytest`:

```bash
# Set PYTHONPATH and run tests
export PYTHONPATH=$PYTHONPATH:.
pytest tests/
```

---

## 🤝 Contributing

Contributions are welcome! Whether it's adding a new parser, improving a report template, or fixing a bug, please feel free to open a Pull Request.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.

## 👤 Author

**İsmail Taşdelen** - [GitHub](https://github.com/ismailtsdln)
