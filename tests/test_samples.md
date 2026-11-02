# EWB Phishing URL Awareness Checker - Test Samples & Execution Log

**Project Name:** EWB Phishing URL Awareness Checker  
**Author:** Egala Naidu  
**Institution:** Sri Venkateswara University College of Engineering  
**Python Version:** Python 3.13.2  
**Operating System:** Windows 11 (64-bit)  
**Test Date:** 2026-11-01  
**Test Framework:** Python `unittest` & Interactive CLI Verification  
**Overall Test Suite Status:** 23 / 23 Tests PASSED (100% Pass Rate)

---

## 1. Overview and Security Principles

All test samples use reserved example domains (such as `.example`, `.invalid` per RFC 2606 / RFC 6761) or documentation IP addresses (RFC 5737 TEST-NET-1: `192.0.2.0/24`). 

> **Important Security Rule:**  
> The application performs static text parsing ONLY. No network requests, socket connections, DNS queries, or browser navigations are ever initiated. Finding zero warning signs does NOT prove that a URL is safe.

---

## 2. Workbook Manual Test Samples (Detailed Results)

### Sample 1: Baseline Clean HTTPS URL
* **Test Input:** `https://www.example.com/login`
* **Expected Result:**  
  * 0 warning signs found.
  * Summary message: `"No listed warning signs found. This does NOT prove safety."`
  * Safety reminder displayed.
* **Actual Result:**  
  * Warning count: `0`
  * Status: `No listed warning signs found. This does NOT prove safety.`
  * Identified Warning Signs: None.
* **Status:** **PASS**
* **Notes & Educational Takeaways:**  
  A typical benign HTTPS URL with a standard domain structure and 3 hostname segments (`www`, `example`, `com`) passes all six heuristic checks. The application properly reinforces that passing these six checks does not certify that the destination is secure or legitimate.

---

### Sample 2: Raw IPv4 Hostname over HTTP
* **Test Input:** `http://192.0.2.10/account`
* **Expected Result:**  
  * 2 warning signs found:
    1. Warning Sign 3: An IPv4 address is used as the hostname.
    2. Warning Sign 6: Use of unencrypted HTTP instead of HTTPS.
  * Summary message: `"REVIEW CAREFULLY: 2 warning sign(s) found."`
* **Actual Result:**  
  * Warning count: `2`
  * Status: `REVIEW CAREFULLY: 2 warning sign(s) found.`
  * Identified Warning Signs:
    * `[1] Warning Sign 3 (IPv4 Hostname): Hostname is a raw IPv4 address ('192.0.2.10'). Legitimate organizations rarely host public user-facing services directly on bare IP addresses without a registered domain name.`
    * `[2] Warning Sign 6 (Insecure HTTP): URL uses unencrypted HTTP instead of HTTPS. Unencrypted connections can be intercepted or modified by malicious parties on the local network or transit path.`
* **Status:** **PASS**
* **Notes & Educational Takeaways:**  
  Phishers often deploy short-lived fake login pages on bare IP addresses to avoid purchasing domains or to evade domain reputation services. Additionally, plain HTTP exposes any submitted credentials to cleartext packet sniffing.

---

### Sample 3: Deceptive Userinfo '@' Symbol
* **Test Input:** `http://example.com@sample.invalid/login`
* **Expected Result:**  
  * 2 warning signs found:
    1. Warning Sign 1: An '@' symbol was detected in the URL.
    2. Warning Sign 6: Use of unencrypted HTTP instead of HTTPS.
  * Summary message: `"REVIEW CAREFULLY: 2 warning sign(s) found."`
* **Actual Result:**  
  * Warning count: `2`
  * Status: `REVIEW CAREFULLY: 2 warning sign(s) found.`
  * Identified Warning Signs:
    * `[1] Warning Sign 1 (@ Symbol): '@' symbol found in URL. Attackers use the '@' symbol to mislead victims; everything before '@' is treated as user credentials, while the actual connection routes to the domain after '@'.`
    * `[2] Warning Sign 6 (Insecure HTTP): URL uses unencrypted HTTP instead of HTTPS. Unencrypted connections can be intercepted or modified by malicious parties on the local network or transit path.`
* **Status:** **PASS**
* **Notes & Educational Takeaways:**  
  According to RFC 3986, characters preceding an `@` symbol represent userinfo/credentials. Victims see `example.com` and assume they are visiting that company, but their browser actually connects to `sample.invalid`.

---

### Sample 4: Deep Nested Subdomains (5 or More Segments)
* **Test Input:** `https://a.b.c.d.e.example.invalid/path`
* **Expected Result:**  
  * 1 warning sign found:
    1. Warning Sign 4: The hostname contains 5 or more segments separated by dots (7 segments detected).
  * Summary message: `"REVIEW CAREFULLY: 1 warning sign(s) found."`
* **Actual Result:**  
  * Warning count: `1`
  * Status: `REVIEW CAREFULLY: 1 warning sign(s) found.`
  * Identified Warning Signs:
    * `[1] Warning Sign 4 (Deep Subdomains): Hostname contains 7 segments separated by dots (5 or more). Excessive domain segments are often used to impersonate legitimate institutions inside nested subdomains.`
* **Status:** **PASS**
* **Notes & Educational Takeaways:**  
  Attackers construct complex domain hierarchies (e.g., `login.bank.verify.security.attacker.invalid`) so the user focuses on the initial keywords and overlooks the actual apex domain. Splitting hostname segments by `.` accurately detects this deceptive pattern.

---

### Sample 5: Punycode-Style Hostname ('xn--')
* **Test Input:** `https://xn--example.invalid/`
* **Expected Result:**  
  * 1 warning sign found:
    1. Warning Sign 5: Punycode-style hostname containing 'xn--'.
  * Summary message: `"REVIEW CAREFULLY: 1 warning sign(s) found."`
* **Actual Result:**  
  * Warning count: `1`
  * Status: `REVIEW CAREFULLY: 1 warning sign(s) found.`
  * Identified Warning Signs:
    * `[1] Warning Sign 5 (Punycode / Homograph): Punycode indicator 'xn--' found in hostname ('xn--example.invalid'). Punycode can be leveraged in homograph spoofing attacks to mimic legitimate brand names with foreign look-alike characters.`
* **Status:** **PASS**
* **Notes & Educational Takeaways:**  
  Internationalized Domain Names (IDNs) beginning with `xn--` allow Unicode characters. In homograph attacks, an attacker replaces Latin letters (like 'a') with identical Cyrillic letters ('а'). A URL parser sees `xn--...`, which immediately exposes the non-ASCII substitution.

---

## 3. Automated Test Suite Execution Summary

The automated test suite in `tests/test_phishing_checker.py` was executed with Python 3.13.2 on Windows 11 using the standard command:
```bash
python -m unittest discover -s tests -v
```

### Complete Test Run Log
| # | Test Method Name | Description / Scenario Tested | Result |
|---|-------------------|--------------------------------|:------:|
| 1 | `test_normal_https_url` | Baseline HTTPS URL (0 warnings, safe wording) | **PASS** |
| 2 | `test_ipv4_hostname_with_http` | IPv4 address + HTTP scheme (2 warnings) | **PASS** |
| 3 | `test_url_with_at_symbol` | '@' symbol deceptive credentials + HTTP | **PASS** |
| 4 | `test_hostname_five_or_more_segments` | Hostname with 7 segments (>= 5 trigger) | **PASS** |
| 5 | `test_hostname_exactly_five_segments` | Boundary test: exactly 5 hostname segments | **PASS** |
| 6 | `test_hostname_fewer_than_five_segments` | Boundary test: 4 segments (no warning) | **PASS** |
| 7 | `test_punycode_hostname` | Hostname containing 'xn--' homograph indicator | **PASS** |
| 8 | `test_url_longer_than_100_characters` | URL with 109 characters (> 100 trigger) | **PASS** |
| 9 | `test_url_exactly_100_characters` | Boundary test: exactly 100 characters (no warning) | **PASS** |
| 10 | `test_empty_string_input` | Empty string `""` handled without crash (`is_valid=False`, 0 warnings) | **PASS** |
| 11 | `test_whitespace_only_input` | Whitespace input handled safely | **PASS** |
| 12 | `test_url_without_scheme_adds_http` | Workbook convention: auto-prepends `http://` | **PASS** |
| 13 | `test_malformed_url_no_crash` | Handles unparseable / malformed strings gracefully | **PASS** |
| 14 | `test_multiple_warning_signs_combined` | Complex URL triggering 4 warning signs simultaneously | **PASS** |
| 15 | `test_workbook_sample_1` | Workbook manual sample 1 verification | **PASS** |
| 16 | `test_workbook_sample_2` | Workbook manual sample 2 verification | **PASS** |
| 17 | `test_workbook_sample_3` | Workbook manual sample 3 verification | **PASS** |
| 18 | `test_workbook_sample_4` | Workbook manual sample 4 verification | **PASS** |
| 19 | `test_workbook_sample_5` | Workbook manual sample 5 verification | **PASS** |
| 20 | `test_is_ipv4_address_valid` | Helper: correctly validates valid IPv4 addresses | **PASS** |
| 21 | `test_is_ipv4_address_invalid` | Helper: rejects out-of-range, non-digit, or incomplete IPs | **PASS** |
| 22 | `test_normalize_url` | Helper: adds scheme only when missing | **PASS** |
| 23 | `test_format_inspection_output` | Verifies terminal output formatting, warnings, reminders | **PASS** |

**Execution Statistics:**
* Ran: 23 tests
* Errors: 0
* Failures: 0
* Execution time: 0.003 seconds
