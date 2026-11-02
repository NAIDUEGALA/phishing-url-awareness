# EWB Phishing URL Awareness Checker

An educational cybersecurity tool built with Python to analyze URL text strings for common phishing indicators and suspicious syntactic patterns.

> **IMPORTANT DISCLAIMER:**  
> This application is strictly an educational text-analysis tool. It checks for selected textual heuristics and **does NOT prove that any URL is safe**. The tool does not open or visit URLs, connect to external servers, or scan networks.

---

## Table of Contents
1. [Project Overview](#1-project-overview)
2. [Problem Statement](#2-problem-statement)
3. [Project Objectives](#3-project-objectives)
4. [Features](#4-features)
5. [Technologies Used](#5-technologies-used)
6. [Folder Structure](#6-folder-structure)
7. [Installation Requirements](#7-installation-requirements)
8. [Step-by-Step Setup Instructions for Windows 11](#8-step-by-step-setup-instructions-for-windows-11)
9. [How to Run the Program](#9-how-to-run-the-program)
10. [Example Input and Output](#10-example-input-and-output)
11. [Testing Instructions](#11-testing-instructions)
12. [Test Results](#12-test-results)
13. [Project Improvements](#13-project-improvements)
14. [Limitations](#14-limitations)
15. [Safety and Ethical Use](#15-safety-and-ethical-use)
16. [Future Enhancements](#16-future-enhancements)
17. [Author and Academic Details](#17-author-and-academic-details)
18. [GitHub Upload Instructions](#18-github-upload-instructions)

---

## 1. Project Overview

The **EWB Phishing URL Awareness Checker** is an introductory cybersecurity and software testing project designed for students and junior developers. It demonstrates how regular expressions (`re`) and URL parsing (`urllib.parse`) can be combined to inspect potentially deceptive web addresses.

Phishing attacks commonly rely on deceptive URL structures to deceive users into disclosing sensitive personal information, credentials, or session tokens. By analyzing the structural components of a URL string without actually opening it, this tool teaches students the anatomy of suspicious links in a completely safe, isolated environment.

---

## 2. Problem Statement

Phishing remains one of the most widespread initial access vectors for cybercriminals worldwide. Attackers frequently use URL obfuscation techniques such as:
- Hiding destination hostnames behind userinfo `@` characters.
- Directing victims to raw IPv4 addresses to bypass domain-based blocklists.
- Layering deceptive subdomains (e.g., `login.security.bank.verify.evil.invalid`).
- Using internationalized homograph characters (`xn--` punycode) to masquerade as trusted brands.
- Relying on unencrypted HTTP connections to intercept user data.

Beginners often lack a clear, practical method to dissect and understand these syntactic warning signs. Furthermore, naive inspection tools can endanger users if they inadvertently fetch or resolve malicious links.

---

## 3. Project Objectives

1. **Safety-First Static Analysis:** Inspect URL text only; never resolve DNS, establish TCP/HTTP connections, or fetch external content.
2. **Heuristic Awareness:** Identify six common warning signs associated with deceptive URLs.
3. **Robust Error Handling:** Handle empty inputs, missing schemes, and malformed strings gracefully without crashing.
4. **Automated Verification:** Provide a comprehensive unit test suite using Python's built-in `unittest` module.
5. **Beginner-Friendly Education:** Explain the security reasoning behind each warning sign in plain language.

---

## 4. Features

The core function `inspect_url(raw_url)` evaluates six distinct warning signs:

| Check # | Warning Sign | Description & Phishing Rationale |
|:-------:|:-------------|:---------------------------------|
| **1** | **`@` Symbol in URL** | In URL syntax (RFC 3986), text before `@` represents user credentials (`user:pass@host`). Attackers use this to trick users into seeing a trusted brand before `@` while the browser routes to the attacker's host after `@`. |
| **2** | **URL Length > 100 Characters** | Excessively long URLs are often used to conceal malicious redirect parameters, embed token payloads, or push suspicious domains out of view on mobile screens. |
| **3** | **IPv4 Hostname** | Uses a raw IPv4 address (e.g., `192.0.2.10`) instead of a registered domain name. Attackers use direct IPs to avoid domain registration costs, verification, and reputation filters. |
| **4** | **5+ Hostname Segments** | Hostname contains five or more dot-separated segments (e.g., `a.b.c.d.e.example.invalid`). Excessive subdomains are frequently configured to mimic authentic services. |
| **5** | **Punycode Hostname (`xn--`)** | Punycode encodes non-ASCII domain characters in ASCII format. Attackers exploit punycode in homograph attacks, substituting visually identical Cyrillic or Greek glyphs for Latin letters. |
| **6** | **Insecure HTTP Scheme** | URL uses unencrypted `http://` rather than `https://`. Plain HTTP traffic is vulnerable to eavesdropping, packet sniffing, and man-in-the-middle (MitM) tampering. |

---

## 5. Technologies Used

* **Python 3.10+** (Developed and tested with Python 3.13.2).
* **`urllib.parse`**: Standard library module for parsing URLs into components (`scheme`, `netloc`, `path`, etc.).
* **`re`**: Standard library module for regular expression pattern matching (IPv4 validation and scheme detection).
* **`unittest`**: Built-in test runner and test case assertions.
* **Markdown**: GitHub-standard documentation format.

> **Zero External Dependencies:** No third-party packages, API keys, or paid services are needed. Everything runs locally and offline.

---

## 6. Folder Structure

```
phishing-url-awareness/
│
├── phishing_checker.py         # Main Python application (core logic + CLI)
├── README.md                   # Comprehensive project documentation
├── requirements.txt            # Dependency documentation (Python stdlib)
├── .gitignore                  # Git ignore rules for Python projects
│
├── tests/
│   ├── test_samples.md         # Manual test sample log with execution outcomes
│   └── test_phishing_checker.py # Automated unittest test suite (23 test cases)
│
└── screenshots/
    ├── README.md               # Guide on how to take authentic Windows 11 screenshots
    ├── sample_run.png          # Screenshot of terminal running the application
    └── test_results.png        # Screenshot of automated test execution output
```

---

## 7. Installation Requirements

1. **Operating System:** Windows 11 (or Windows 10, macOS, Linux).
2. **Python:** Python 3.10 or newer.
   * Verify by opening PowerShell and typing: `python --version` (or `py --version`).
3. **No External Packages:** No `pip install` commands are needed because all modules (`urllib.parse`, `re`, `unittest`) are built directly into Python.

---

## 8. Step-by-Step Setup Instructions for Windows 11

### Step 1: Open Terminal in the Project Directory
1. Open **File Explorer** and navigate to your project folder:
   `c:\Users\Naidu E\Downloads\phishing url awareness checker\phishing-url-awareness`
2. Right-click an empty area inside the folder and select **Open in Terminal**, or press `Win + R`, type `powershell`, and navigate to the directory:
   ```powershell
   cd "c:\Users\Naidu E\Downloads\phishing url awareness checker\phishing-url-awareness"
   ```

### Step 2: Verify Python Installation
In your PowerShell terminal, run:
```powershell
python --version
```
* If Python is recognized, it will display something like `Python 3.13.2`.
* If `python` is not recognized, try `py --version`.
* If Python is not installed, download it from the official website [python.org](https://www.python.org/) and make sure to check the box **"Add Python to PATH"** during installation.

---

## 9. How to Run the Program

Start the interactive command-line interface with:
```powershell
python phishing_checker.py
```
*(If `python` is not in your PATH, use `py phishing_checker.py`)*

### Interactive Commands:
* **Inspect a URL:** Enter any URL string (e.g., `https://www.example.com/login`) and press **Enter**.
* **Exit the Program:** Type `q`, `quit`, or `exit` and press **Enter**.

---

## 10. Example Input and Output

### Example 1: Baseline Clean URL
```text
Enter URL to inspect: https://www.example.com/login
-----------------------------------------------------------------
URL Tested       : https://www.example.com/login
-----------------------------------------------------------------
STATUS           : No listed warning signs found. This does NOT prove safety.
-----------------------------------------------------------------
No suspicious indicators from the six check categories were found.
-----------------------------------------------------------------
IMPORTANT SAFETY REMINDER:
  Text pattern checks are educational indicators, NOT a guarantee of safety.
  Clever phishing attacks can look completely normal, and legitimate links
  may occasionally trigger warnings. Never enter credentials on untrusted links.
-----------------------------------------------------------------
```

### Example 2: Suspicious IPv4 Address over Plain HTTP
```text
Enter URL to inspect: http://192.0.2.10/account
-----------------------------------------------------------------
URL Tested       : http://192.0.2.10/account
-----------------------------------------------------------------
STATUS           : REVIEW CAREFULLY: 2 warning sign(s) found.
-----------------------------------------------------------------
IDENTIFIED WARNING SIGNS:
  [1] Warning Sign 3 (IPv4 Hostname): Hostname is a raw IPv4 address ('192.0.2.10'). Legitimate organizations rarely host public user-facing services directly on bare IP addresses without a registered domain name.
  [2] Warning Sign 6 (Insecure HTTP): URL uses unencrypted HTTP instead of HTTPS. Unencrypted connections can be intercepted or modified by malicious parties on the local network or transit path.
-----------------------------------------------------------------
IMPORTANT SAFETY REMINDER:
  Text pattern checks are educational indicators, NOT a guarantee of safety.
  Clever phishing attacks can look completely normal, and legitimate links
  may occasionally trigger warnings. Never enter credentials on untrusted links.
-----------------------------------------------------------------
```

---

## 11. Testing Instructions

To run the full automated test suite using Python's `unittest` framework:

```powershell
python -m unittest discover -s tests -v
```

If you prefer to execute the test script directly:
```powershell
python tests/test_phishing_checker.py
```

---

## 12. Test Results

The automated test suite was executed on Windows 11 with Python 3.13.2. All **23 test cases passed** with zero errors and zero failures.

```text
test_empty_string_input (test_phishing_checker.TestPhishingChecker.test_empty_string_input) ... ok
test_format_inspection_output (test_phishing_checker.TestPhishingChecker.test_format_inspection_output) ... ok
test_hostname_exactly_five_segments (test_phishing_checker.TestPhishingChecker.test_hostname_exactly_five_segments) ... ok
test_hostname_fewer_than_five_segments (test_phishing_checker.TestPhishingChecker.test_hostname_fewer_than_five_segments) ... ok
test_hostname_five_or_more_segments (test_phishing_checker.TestPhishingChecker.test_hostname_five_or_more_segments) ... ok
test_ipv4_hostname_with_http (test_phishing_checker.TestPhishingChecker.test_ipv4_hostname_with_http) ... ok
test_is_ipv4_address_invalid (test_phishing_checker.TestPhishingChecker.test_is_ipv4_address_invalid) ... ok
test_is_ipv4_address_valid (test_phishing_checker.TestPhishingChecker.test_is_ipv4_address_valid) ... ok
test_malformed_url_no_crash (test_phishing_checker.TestPhishingChecker.test_malformed_url_no_crash) ... ok
test_multiple_warning_signs_combined (test_phishing_checker.TestPhishingChecker.test_multiple_warning_signs_combined) ... ok
test_normal_https_url (test_phishing_checker.TestPhishingChecker.test_normal_https_url) ... ok
test_normalize_url (test_phishing_checker.TestPhishingChecker.test_normalize_url) ... ok
test_punycode_hostname (test_phishing_checker.TestPhishingChecker.test_punycode_hostname) ... ok
test_url_exactly_100_characters (test_phishing_checker.TestPhishingChecker.test_url_exactly_100_characters) ... ok
test_url_longer_than_100_characters (test_phishing_checker.TestPhishingChecker.test_url_longer_than_100_characters) ... ok
test_url_with_at_symbol (test_phishing_checker.TestPhishingChecker.test_url_with_at_symbol) ... ok
test_url_without_scheme_adds_http (test_phishing_checker.TestPhishingChecker.test_url_without_scheme_adds_http) ... ok
test_whitespace_only_input (test_phishing_checker.TestPhishingChecker.test_whitespace_only_input) ... ok
test_workbook_sample_1 (test_phishing_checker.TestPhishingChecker.test_workbook_sample_1) ... ok
test_workbook_sample_2 (test_phishing_checker.TestPhishingChecker.test_workbook_sample_2) ... ok
test_workbook_sample_3 (test_phishing_checker.TestPhishingChecker.test_workbook_sample_3) ... ok
test_workbook_sample_4 (test_phishing_checker.TestPhishingChecker.test_workbook_sample_4) ... ok
test_workbook_sample_5 (test_phishing_checker.TestPhishingChecker.test_workbook_sample_5) ... ok

----------------------------------------------------------------------
Ran 23 tests in 0.003s

OK
```

Full details on test cases and manual samples are documented in [`tests/test_samples.md`](tests/test_samples.md).

---

## 13. Project Improvements

The application includes all four specified enhancements:

1. **Improvement A (Repeated URL Checking):**  
   Users can test as many URLs as desired in an interactive loop without relaunching the program.
2. **Improvement B (Graceful Quit Options):**  
   Users can exit cleanly at any time by typing `q`, `quit`, or `exit`.
3. **Improvement C (Malformed-Input Handling):**  
   URL parsing exceptions, missing hostnames, empty strings, and bracket mismatches are caught safely. Friendly messages are displayed, and the application never crashes.
4. **Improvement D (Accurate Warning Summary):**  
   Clear summary headers are displayed (e.g., `REVIEW CAREFULLY: 2 warning sign(s) found.` vs. `No listed warning signs found. This does NOT prove safety.`). Parsing errors and empty inputs are strictly separated from warning sign counts.
5. **Educational Explanations:**  
   Each warning sign is accompanied by plain-English context explaining why the pattern is suspicious from a cybersecurity standpoint.

---

## 14. Limitations

* **Heuristic Only:** Static text heuristics cannot detect freshly registered phishing domains that mimic genuine brands without triggering length or punycode rules.
* **No Real-Time Threat Intelligence:** The tool does not consult live blocklists (e.g., Google Safe Browsing, PhishTank) to maintain offline privacy.
* **False Positives:** Legitimate local network URLs (e.g., internal router configuration at `http://192.168.1.1`) will trigger IPv4 and HTTP warnings.
* **False Negatives:** Attackers can register standard HTTPS domains on modern TLDs with fewer than 5 segments that pass all six text checks.

---

## 15. Safety and Ethical Use

This project was built strictly for **educational and defensive training**:
* **No Network Traffic:** The code does not issue HTTP `GET`/`POST` requests, socket connections, or DNS queries.
* **Safe Sample Strings:** Testing uses reserved documentation IPs (RFC 5737 `192.0.2.0/24`) and invalid TLDs (RFC 2606 `.invalid`, `.example`).
* **Privacy Preserving:** No user input, history, passwords, or personal data are stored or transmitted.

---

## 16. Future Enhancements

* Add detection for Top-Level Domain (TLD) brand spoofing (e.g., `.security-update.com`).
* Add Levenshtein distance calculations to compare hostnames against known brand dictionaries (e.g., detecting `paypa1.com` vs `paypal.com`).
* Add batch processing mode to inspect URLs from a local text file.
* Export inspection results to structured JSON or CSV format for classroom assignments.

---

## 17. Author and Academic Details

* **Author:** Egala Naidu
* **Course / Project:** Cybersecurity Mini-Project (EWB Phishing URL Awareness)
* **Institution:** Sri Venkateswara University College of Engineering
* **Date:** November 2026

---

## 18. GitHub Upload Instructions

To upload this project to your personal GitHub account:

### Method 1: Using Git via Terminal (Recommended)

1. Create a new **empty public repository** on [github.com](https://github.com/new) named `phishing-url-awareness`.
   *(Do NOT check the box to initialize with a README, .gitignore, or license, as we already created them).*
2. Open PowerShell in your project folder:
   ```powershell
   cd "c:\Users\Naidu E\Downloads\phishing url awareness checker\phishing-url-awareness"
   ```
3. Initialize the Git repository:
   ```powershell
   git init
   ```
4. Stage all files:
   ```powershell
   git add .
   ```
5. Commit your work:
   ```powershell
   git commit -m "Initial release: EWB Phishing URL Awareness Checker"
   ```
6. Set the default branch to `main`:
   ```powershell
   git branch -M main
   ```
7. Link to your GitHub repository:
   ```powershell
   git remote add origin https://github.com/NAIDUEGALA/phishing-url-awareness.git
   ```
8. Push your code to GitHub:
   ```powershell
   git push -u origin main
   ```

### Method 2: Using GitHub Web Interface (Drag and Drop)
1. Go to [github.com](https://github.com/) and click **New repository**.
2. Name the repository `phishing-url-awareness`.
3. Click **Create repository**.
4. On the setup page, click the link: **"uploading an existing file"**.
5. Drag and drop all the files from the `phishing-url-awareness` folder into GitHub in your browser.
6. Commit the files directly on the page.
