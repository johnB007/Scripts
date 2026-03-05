<div align="center">

# 🛡️ MDAV Analyzer

### Microsoft Defender Performance & Status Analysis Tool

[![PowerShell](https://img.shields.io/badge/PowerShell-5.0+-blue.svg)](https://github.com/PowerShell/PowerShell)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MDE](https://img.shields.io/badge/MDE-Live%20Response-orange.svg)](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/)

**Automated performance analysis and status reporting for Microsoft Defender Antivirus**

[Features](#-features) • [Quick Start](#-quick-start) • [Usage](#-usage) • [Output](#-output-structure) • [Examples](#-examples)

---

</div>

## 📋 Overview

A production-ready PowerShell automation script designed for **SOC analysts**, **security teams**, and **incident responders** to analyze Microsoft Defender for Endpoint (MDE) antivirus performance in real-time. 

🎯 **Perfect for:**
- Identifying performance bottlenecks before implementing exclusions
- Remote diagnostics via MDE Live Response
- Fleet-wide performance baselining
- Pre/post-tuning impact assessment

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔍 Dual-Mode Analysis
- **Status Collection**: Current AV configuration snapshot
- **Performance Recording**: 5-minute automated ETL capture
- **Zero Touch**: Fully autonomous execution (no prompts)

</td>
<td width="50%">

### 📦 Streamlined Output
- **Single ZIP Archive**: All reports compressed automatically
- **Timestamped**: Hostname + timestamp in all filenames
- **Portable**: Works on any Windows 10/11 or Server 2019+ system

</td>
</tr>
<tr>
<td width="50%">

### 🚀 Live Response Ready
- **runscript** compatible for remote deployment
- **SYSTEM context** execution support
- **Automatic cleanup** of temporary ETL files

</td>
<td width="50%">

### 📊 Comprehensive Metrics
- Top 50 files by scan duration
- Top 50 processes triggering scans
- Top 50 extensions by performance impact
- Top 50 paths with highest overhead

</td>
</tr>
</table>

## 🎯 Part 1️⃣: Execution in Live Response

<img width="1793" height="846" alt="image" src="https://github.com/user-attachments/assets/efd7dd57-ebcd-4d11-937c-895690475e03" />
<img width="1801" height="829" alt="image" src="https://github.com/user-attachments/assets/75ebe703-11a1-4ec8-93b5-af1e224af355" />
<img width="1800" height="620" alt="image" src="https://github.com/user-attachments/assets/5b6cfe7e-b691-43ec-8094-68897b53d240" />
<img width="1854" height="331" alt="image" src="https://github.com/user-attachments/assets/a50acb22-21b3-4725-bba6-d38ee33faa83" />


### Part 2️⃣: Performance Analysis (5-Minute Window)
| Dataset | Description | Rows |
|---------|-------------|------|
| **TopFiles.csv** | Files with longest scan durations | 50 |
| **TopProcesses.csv** | Processes triggering most scans | 50 |
| **TopExtensions.csv** | File types by performance impact | 50 |
| **TopPaths.csv** | Filesystem locations with highest overhead | 50 |
| **TopFilesPerProcess.csv** | File/process scan relationships | Variable |
| **TopPathsPerExtension.csv** | Path/extension cross-analysis | Variable |

<img width="1452" height="260" alt="image" src="https://github.com/user-attachments/assets/c716648c-a728-4d3f-b0b0-5841489aabd4" />


