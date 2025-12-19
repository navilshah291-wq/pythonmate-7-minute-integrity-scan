# 7-Minute SAP GOS Integrity Scan

**Diagnostic Reference Implementation** - *Not a Product*

Maintained by PythonMate
Enterprise SAP Content Integrity Diagnostics
https://pythonmate.com

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

## Purpose & Positioning

This repository is a **diagnostic reference implementation** demonstrating Python-to-SAP connectivity for GOS (Generic Object Services) integrity analysis. This tool:

- **Reveals integrity decay** in SAP GOS tables (SOFFCONT1, SRGBTBREL, SOFFPHIO)
- **Does NOT fix** any identified issues
- **Does NOT provide** remediation or cleanup capabilities
- **Requires enterprise engagement** for actual remediation activities
- **Operates in read-only mode only** with zero-ABAP approach

This tool surfaces risks and technical debt but does not resolve them. Actual remediation requires a separate, private PythonMate engagement.

---

## Target Audience

- SAP Basis Administrators
- S/4HANA Migration Architects
- SAP Security & Audit Teams
- Enterprise Architecture Groups

---

## Core Capabilities (Diagnostic-Only)

- **Read-Only Access**: Uses RFC_READ_TABLE and metadata functions only
- **7-Minute Execution Window**: Designed for evaluation, not comprehensive analysis
- **Risk Identification**: Detects orphaned SOFFCONT1 entries without remediation
- **Enterprise Safety**: Zero write operations, zero binary access, zero transport impact

### What This Tool CANNOT Do:
- Perform cleanup operations
- Execute remediation logic
- Access binary data (CLUSTD column)
- Create transports
- Modify SAP tables
- Provide self-service fixes

The diagnostic validates attachment integrity by cross-checking GOS relationship entries (SRGBTBREL) against physical document metadata (SOFFPHIO) to identify orphaned or unreachable content without accessing binary payloads.

---

## Quick Start

### Prerequisites
- Python 3.8+
- SAP NetWeaver RFC SDK
- Valid SAP credentials with S_TABU_NAM authorization (table name access only)

### Installation
```bash
git clone https://github.com/pythonmate/7-minute-integrity-scan.git
cd 7-minute-integrity-scan
pip install -r requirements.txt
```

### Run Diagnostic Scan
```bash
python src/cli/main.py scan --system PRD --client 100 --host sapserver.company.com --sysnr 00 --user RFC_USER --password 'password'
```

Output: `reports/GOS_Integrity_Audit_PRD_YYYYMMDD_HHMMSS.pdf`

### Validate Connection Only
```bash
python src/cli/main.py validate-connection --host sapserver.company.com --sysnr 00 --client 100 --user RFC_USER --password 'password'
```

---

## Security Model

This tool implements strict read-only operations:
- **Zero Data Modification**: No write, update, or delete operations
- **No Binary Access**: Never accesses CLUSTD (binary data) column
- **Metadata Only**: Analyzes relationships, not content
- **Audit Safe**: Designed to pass enterprise security reviews

See [SECURITY_MODEL.md](SECURITY_MODEL.md) for detailed security assurance.

---

## When NOT to run this diagnostic

- On productive systems without Basis approval
- As a substitute for migration test cycles
- For cleanup or deletion decisions
- For ArchiveLink design

## Enterprise Considerations

This diagnostic tool reveals opportunities but does **not address** them. Remediation activities (cleanup, optimization, migration) require a separate enterprise engagement with PythonMate due to:

- Complexity of safe GOS object deletion
- Risk of breaking business workflows
- Need for comprehensive testing environments
- Compliance and audit requirements

---

## Getting Started

### For SAP Basis Teams
This diagnostic is designed for pre-production environments to identify content integrity risks before they impact production systems.

### For S/4HANA Migration Architects
Use this tool to quantify GOS attachment bloat and plan cleanup strategies during your migration timeline.

### For Security & Audit Teams
Validate that GOS relationships are consistent and identify orphaned content that may pose compliance risks.

### Download & Installation

Ready to evaluate SAP GOS integrity in your environment?

```bash
git clone https://github.com/pythonmate/7-minute-integrity-scan.git
cd 7-minute-integrity-scan
pip install -r requirements.txt
```

### Next Steps
After running your diagnostic scan, engage with PythonMate for comprehensive remediation planning and execution.

## License

MIT License - See [LICENSE](LICENSE)