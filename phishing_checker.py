"""
EWB Phishing URL Awareness Checker
===================================
Author: Egala Naidu
Institution: Sri Venkateswara University College of Engineering
Educational cybersecurity project demonstrating static text analysis
of URLs to identify common phishing warning signs.

Security Principles:
- This program performs text checks ONLY.
- It NEVER visits, pings, fetches, or establishes a network connection to any URL.
- It NEVER transmits data to external servers or APIs.
- Absence of warning signs does NOT prove that a URL is safe.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any, Dict, List, Optional


class InspectionResult(dict):
    """Structured result returned by inspect_url.

    Inherits from dict so results can be accessed either as a dictionary
    (e.g., result['warnings']) or via attributes (e.g., result.warnings).
    """

    def __init__(
        self,
        raw_url: str = "",
        normalized_url: str = "",
        warnings: Optional[List[str]] = None,
        summary: str = "",
        is_valid: bool = True,
        error: Optional[str] = None,
    ) -> None:
        warnings_list = warnings if warnings is not None else []
        super().__init__(
            raw_url=raw_url,
            normalized_url=normalized_url,
            warnings=warnings_list,
            warning_count=len(warnings_list),
            summary=summary,
            is_valid=is_valid,
            error=error,
        )

    @property
    def raw_url(self) -> str:
        return self["raw_url"]

    @property
    def normalized_url(self) -> str:
        return self["normalized_url"]

    @property
    def warnings(self) -> List[str]:
        return self["warnings"]

    @property
    def warning_count(self) -> int:
        return self["warning_count"]

    @property
    def summary(self) -> str:
        return self["summary"]

    @property
    def is_valid(self) -> bool:
        return self["is_valid"]

    @property
    def error(self) -> Optional[str]:
        return self["error"]


def is_ipv4_address(hostname: str) -> bool:
    """Check if the provided hostname is a valid IPv4 address (four octets, 0-255).

    Args:
        hostname: The hostname string to evaluate.

    Returns:
        True if the hostname matches an IPv4 format, False otherwise.
    """
    if not hostname:
        return False
    # Regular expression for matching four dot-separated integer strings
    match = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", hostname)
    if not match:
        return False
    # Validate each octet is in the valid IPv4 range 0 through 255
    return all(0 <= int(octet) <= 255 for octet in match.groups())


def normalize_url(raw_url: str) -> str:
    """Normalize input URL according to workbook convention.

    If the URL has no scheme, prepend 'http://' before parsing.

    Args:
        raw_url: The unparsed URL string.

    Returns:
        The normalized URL string with a scheme.
    """
    stripped = raw_url.strip()
    # Check if a scheme is already present (e.g., http://, https://, ftp://)
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", stripped):
        return f"http://{stripped}"
    return stripped


def inspect_url(raw_url: str) -> InspectionResult:
    """Inspect a URL string for six specific phishing warning signs.

    The six checks are:
    1. An '@' symbol in the URL.
    2. URL length greater than 100 characters.
    3. An IPv4 address used as the hostname.
    4. Five or more hostname segments separated by dots.
    5. A punycode-style hostname containing 'xn--'.
    6. Use of HTTP instead of HTTPS.

    Args:
        raw_url: The raw URL string provided by the user.

    Returns:
        InspectionResult object containing findings, warning count, and summary.
    """
    # Handle empty or whitespace-only input without crashing
    if not raw_url or not raw_url.strip():
        return InspectionResult(
            raw_url=raw_url,
            normalized_url="",
            warnings=[],
            summary="Input cannot be empty. Please enter a valid URL.",
            is_valid=False,
            error="Empty URL input",
        )

    cleaned_url = raw_url.strip()
    normalized_url = normalize_url(cleaned_url)

    # Safely parse URL components using urllib.parse.urlparse
    try:
        parsed = urllib.parse.urlparse(normalized_url)
    except Exception as exc:
        # Catch URL parsing errors gracefully (Improvement C)
        return InspectionResult(
            raw_url=cleaned_url,
            normalized_url=normalized_url,
            warnings=[],
            summary=f"Malformed URL error: {exc}",
            is_valid=False,
            error=str(exc),
        )

    # Safely extract the hostname (lowercased without port)
    hostname = parsed.hostname or ""

    # Additional check: malformed URL with no hostname and invalid netloc
    if not hostname and not parsed.netloc and not parsed.path:
        return InspectionResult(
            raw_url=cleaned_url,
            normalized_url=normalized_url,
            warnings=[],
            summary="Malformed URL format: No host or path could be identified.",
            is_valid=False,
            error="Malformed URL structure",
        )

    warnings: List[str] = []

    # -------------------------------------------------------------
    # Check 1: An '@' symbol in the URL
    # -------------------------------------------------------------
    # In URL standards (RFC 3986), characters before '@' represent user credentials.
    # Phishers exploit this by writing 'http://trusted-brand.com@evil-domain.com'
    # so the user sees the trusted name, but the browser visits evil-domain.com.
    if "@" in cleaned_url:
        warnings.append(
            "Warning Sign 1 (@ Symbol): '@' symbol found in URL. "
            "Attackers use the '@' symbol to mislead victims; everything before "
            "'@' is treated as user credentials, while the actual connection routes "
            "to the domain after '@'."
        )

    # -------------------------------------------------------------
    # Check 2: URL length greater than 100 characters
    # -------------------------------------------------------------
    # Excessively long URLs are often crafted to hide suspicious tokens,
    # conceal deep redirects, or push the actual destination domain offscreen.
    if len(cleaned_url) > 100:
        warnings.append(
            f"Warning Sign 2 (Long URL): URL length is {len(cleaned_url)} characters "
            "(greater than 100). Excessively long URLs may be used to obscure malicious "
            "redirects or hide the true destination."
        )

    # -------------------------------------------------------------
    # Check 3: An IPv4 address used as the hostname
    # -------------------------------------------------------------
    # Legitimate services almost always use human-readable domain names.
    # Phishers and attackers often use direct IPv4 addresses to bypass
    # domain registration filters, reputation databases, or take-down notices.
    if is_ipv4_address(hostname):
        warnings.append(
            f"Warning Sign 3 (IPv4 Hostname): Hostname is a raw IPv4 address ('{hostname}'). "
            "Legitimate organizations rarely host public user-facing services directly on "
            "bare IP addresses without a registered domain name."
        )

    # -------------------------------------------------------------
    # Check 4: Five or more hostname segments separated by dots
    # -------------------------------------------------------------
    # Attackers create multiple subdomain layers (e.g., login.bank.verify.security.attacker.invalid)
    # to spoof trusted brand names and confuse users into trusting the link.
    hostname_segments = [seg for seg in hostname.split(".") if seg]
    if len(hostname_segments) >= 5:
        warnings.append(
            f"Warning Sign 4 (Deep Subdomains): Hostname contains {len(hostname_segments)} "
            "segments separated by dots (5 or more). Excessive domain segments are often used "
            "to impersonate legitimate institutions inside nested subdomains."
        )

    # -------------------------------------------------------------
    # Check 5: A punycode-style hostname containing 'xn--'
    # -------------------------------------------------------------
    # Punycode encodes Internationalized Domain Names (IDNs) in ASCII.
    # In homograph attacks, attackers register look-alike domains using
    # non-Latin characters (e.g., Cyrillic 'a' vs Latin 'a') that display
    # internally as 'xn--...' but appear identical to genuine brands in browsers.
    if "xn--" in hostname.lower():
        warnings.append(
            f"Warning Sign 5 (Punycode / Homograph): Punycode indicator 'xn--' found in "
            f"hostname ('{hostname}'). Punycode can be leveraged in homograph spoofing "
            "attacks to mimic legitimate brand names with foreign look-alike characters."
        )

    # -------------------------------------------------------------
    # Check 6: Use of HTTP instead of HTTPS
    # -------------------------------------------------------------
    # Plain HTTP does not encrypt communication, exposing user credentials,
    # session cookies, and sensitive information to network eavesdropping and tampering.
    if parsed.scheme.lower() == "http":
        warnings.append(
            "Warning Sign 6 (Insecure HTTP): URL uses unencrypted HTTP instead of HTTPS. "
            "Unencrypted connections can be intercepted or modified by malicious parties "
            "on the local network or transit path."
        )

    # Determine summary message based on count (Improvement D)
    if warnings:
        summary = f"REVIEW CAREFULLY: {len(warnings)} warning sign(s) found."
    else:
        summary = "No listed warning signs found. This does NOT prove safety."

    return InspectionResult(
        raw_url=cleaned_url,
        normalized_url=normalized_url,
        warnings=warnings,
        summary=summary,
        is_valid=True,
        error=None,
    )


def format_inspection_output(result: InspectionResult) -> str:
    """Format an InspectionResult into a beginner-friendly command-line report.

    Args:
        result: The InspectionResult object.

    Returns:
        Formatted multi-line string for terminal display.
    """
    lines: List[str] = []
    lines.append("-" * 65)
    lines.append(f"URL Tested       : {result.raw_url}")
    if result.normalized_url and result.normalized_url != result.raw_url:
        lines.append(f"Normalized URL   : {result.normalized_url} (added http://)")
    lines.append("-" * 65)

    if not result.is_valid:
        lines.append(f"[!] INPUT ERROR  : {result.summary}")
        lines.append("-" * 65)
        return "\n".join(lines)

    lines.append(f"STATUS           : {result.summary}")
    lines.append("-" * 65)

    if result.warnings:
        lines.append("IDENTIFIED WARNING SIGNS:")
        for idx, warning in enumerate(result.warnings, start=1):
            lines.append(f"  [{idx}] {warning}")
    else:
        lines.append("No suspicious indicators from the six check categories were found.")

    lines.append("-" * 65)
    lines.append("IMPORTANT SAFETY REMINDER:")
    lines.append(
        "  Text pattern checks are educational indicators, NOT a guarantee of safety.\n"
        "  Clever phishing attacks can look completely normal, and legitimate links\n"
        "  may occasionally trigger warnings. Never enter credentials on untrusted links."
    )
    lines.append("-" * 65)
    return "\n".join(lines)


def run_cli() -> None:
    """Run the interactive command-line interface.

    Supports repeated URL checking (Improvement A) and quitting via
    'q', 'quit', or 'exit' (Improvement B).
    """
    banner = """
=================================================================
# EWB PHISHING URL AWARENESS CHECKER
=================================================================
Educational cybersecurity project
Text checks only - this program does not open URLs.
=================================================================
Type a URL to inspect, or type 'q', 'quit', or 'exit' to close.
"""
    print(banner)

    while True:
        try:
            user_input = input("\nEnter URL to inspect: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n\nSession terminated by user. Goodbye!")
            break

        # Check for quit commands (Improvement B)
        if user_input.lower() in ("q", "quit", "exit"):
            print("\nExiting EWB Phishing URL Awareness Checker. Stay safe online!\n")
            break

        # Check for empty input (Improvement C & Requirement 4)
        if not user_input:
            print("[INFO] Input was empty. Please enter a URL string to inspect.")
            continue

        # Inspect the URL and display formatted findings
        result = inspect_url(user_input)
        print(format_inspection_output(result))


if __name__ == "__main__":
    run_cli()
