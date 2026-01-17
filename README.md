# 💠 VectorFuzz

> **Enterprise-Grade Web Vulnerability Scanner**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)
![GUI](https://img.shields.io/badge/GUI-CustomTkinter-0078D6?style=for-the-badge&logo=tcl)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

---

## Overview

**VectorFuzz** is a modern, GUI-based web application security scanner built with Python and CustomTkinter. It performs automated crawling, fuzzing, and vulnerability detection with advanced evasion techniques and professional-grade reporting.

> ⚠️ **For educational and authorized security testing only.**
> Scanning systems without permission is illegal.

---

## Project Highlights

* **Fully offline operation:** No external API calls or data exfiltration.
* **No cloud dependency:** Runs entirely on your local machine.
* **Real-time vulnerability intelligence:** Live logging of attack vectors and responses.
* **Enterprise-style UI & reporting:** Dark-mode dashboard with comprehensive data export.
* **Designed for cybersecurity learning & red-team simulation:** Understand how attacks work in real-time.

---

## Key Features

### Vulnerability Detection
* **SQL Injection:** Error-based, Blind (time-based), and Header-based (User-Agent injection).
* **Cross-Site Scripting (XSS):** Reflected XSS detection.
* **Advanced Vectors:** Local File Inclusion (LFI) and Remote Code Execution (RCE).

### Advanced Crawling Engine
* **Heuristic Crawling:** Depth control with intelligent endpoint generation.
* **Auto-Parsing:** Automatically processes `robots.txt` and `sitemap.xml`.
* **Discovery:** Comprehensive form discovery and parameter extraction.

### Payload Mutation & WAF Evasion
* **Obfuscation:** URL encoding, double encoding, and SQL comment obfuscation.
* **Evasion:** Randomized payload casing and Header spoofing (X-Forwarded-For, Client-IP).
* **Levels:** Configurable evasion modes (Low, Medium, High, Insane).

### Performance & Control
* **Multi-threaded Scanning:** Adjustable concurrency (1–30 threads).
* **Real-time Control:** Pause and resume scans instantly.
* **Live Statistics:** Monitor requests sent, nodes crawled, and vulnerabilities found.

---

## Professional Reporting

Export scan results in multiple formats:

* ✅ **HTML** (Interactive dashboard)
* ✅ **JSON** (Raw data)
* ✅ **PDF** (Summary report)

**Each finding includes:**
* Vulnerability type
* Severity
* CWE reference
* Affected URL
* Injected payload
* Remediation strategy

---

## Installation

### 1. Clone the repository
```bash
git clone [https://github.com/BGx-11/VectorFuzz.git](https://github.com/BGx-11/VectorFuzz.git)
cd VectorFuzz

```

### 2. Install dependencies

```bash
pip install -r requirements.txt

```

*Or manually install required packages:*

```bash
pip install customtkinter requests beautifulsoup4 fpdf

```

> **Note:** PDF export requires `fpdf`. HTML & JSON exports will work without it.

---

## Usage

1. Run the application:
```bash
python main.py

```


2. **Target:** Enter the target URL.
3. **Profile:** Choose **Standard** or **Intense** profile.
4. **Configure:** Adjust scan parameters (threads, depth, evasion) if needed.
5. **Scan:** Click **INITIALIZE SCAN**.
6. **Report:** Monitor live results and export reports via the "Export Data" tab.

---

## Legal Disclaimer

**This tool is intended only for:**

* Educational purposes
* Authorized penetration testing
* Security research on systems you own or have permission to test

**The developer is not responsible for misuse or illegal activity.** Scanning systems without permission is illegal.

---

## License

Licensed under the **MIT License**.

---


<p align="center">
<strong>Developed by BGx (Devansh Agarwal)</strong><br>
<em>Cybersecurity Enthusiast & Developer</em>
</p>
