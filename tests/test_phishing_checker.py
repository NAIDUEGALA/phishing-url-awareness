"""
Automated Test Suite for EWB Phishing URL Awareness Checker
============================================================
Uses Python's built-in `unittest` framework to verify:
1. Normal example HTTPS URL (zero warnings)
2. HTTP URL containing a documentation IPv4 address
3. URL containing an '@' symbol
4. Hostname with five or more segments
5. Punycode-style hostname ('xn--')
6. URL longer than 100 characters
7. Empty / whitespace-only input
8. URL without a scheme (adds http:// per workbook convention)
9. Malformed URL input
10. URL with multiple warning signs
11. Workbook 5 manual test samples
12. Helper functions (is_ipv4_address, normalize_url, format_inspection_output)
"""

from __future__ import annotations

import os
import sys
import unittest

# Ensure the parent directory containing phishing_checker.py is in the search path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from phishing_checker import (
    InspectionResult,
    format_inspection_output,
    inspect_url,
    is_ipv4_address,
    normalize_url,
)


class TestPhishingChecker(unittest.TestCase):
    """Unit test cases covering all required detection checks and edge cases."""

    # -------------------------------------------------------------
    # 1. Normal example HTTPS URL (Baseline Safe Domain)
    # -------------------------------------------------------------
    def test_normal_https_url(self) -> None:
        """A standard HTTPS URL should trigger zero warning signs."""
        url = "https://www.example.com/login"
        result = inspect_url(url)

        self.assertTrue(result.is_valid)
        self.assertEqual(result.warning_count, 0)
        self.assertEqual(len(result.warnings), 0)
        self.assertEqual(
            result.summary,
            "No listed warning signs found. This does NOT prove safety.",
        )
        self.assertIsNone(result.error)

    # -------------------------------------------------------------
    # 2. HTTP URL containing a documentation IPv4 address
    # -------------------------------------------------------------
    def test_ipv4_hostname_with_http(self) -> None:
        """An HTTP URL with a raw IPv4 address should trigger 2 warning signs:
        - Warning Sign 3: IPv4 address used as hostname
        - Warning Sign 6: HTTP instead of HTTPS
        """
        # 192.0.2.10 is an IETF RFC 5737 TEST-NET-1 documentation IP address
        url = "http://192.0.2.10/account"
        result = inspect_url(url)

        self.assertTrue(result.is_valid)
        self.assertEqual(result.warning_count, 2)
        self.assertEqual(
            result.summary,
            "REVIEW CAREFULLY: 2 warning sign(s) found.",
        )
        # Check that specific warnings are present
        warnings_str = " ".join(result.warnings)
        self.assertIn("Warning Sign 3 (IPv4 Hostname)", warnings_str)
        self.assertIn("Warning Sign 6 (Insecure HTTP)", warnings_str)

    # -------------------------------------------------------------
    # 3. URL containing an '@' symbol
    # -------------------------------------------------------------
    def test_url_with_at_symbol(self) -> None:
        """A URL containing '@' should trigger Warning Sign 1."""
        url = "http://example.com@sample.invalid/login"
        result = inspect_url(url)

        self.assertTrue(result.is_valid)
        # Triggers Sign 1 (@ symbol) and Sign 6 (HTTP)
        self.assertEqual(result.warning_count, 2)
        warnings_str = " ".join(result.warnings)
        self.assertIn("Warning Sign 1 (@ Symbol)", warnings_str)
        self.assertIn("Warning Sign 6 (Insecure HTTP)", warnings_str)

    # -------------------------------------------------------------
    # 4. Hostname with five or more segments
    # -------------------------------------------------------------
    def test_hostname_five_or_more_segments(self) -> None:
        """A hostname with >= 5 dot-separated segments triggers Warning Sign 4."""
        # 7 segments: 'a', 'b', 'c', 'd', 'e', 'example', 'invalid'
        url = "https://a.b.c.d.e.example.invalid/path"
        result = inspect_url(url)

        self.assertTrue(result.is_valid)
        self.assertEqual(result.warning_count, 1)
        self.assertIn("Warning Sign 4 (Deep Subdomains)", result.warnings[0])
        self.assertIn("7 segments", result.warnings[0])

    def test_hostname_exactly_five_segments(self) -> None:
        """A hostname with exactly 5 segments should also trigger Warning Sign 4."""
        # 5 segments: 'sub3', 'sub2', 'sub1', 'example', 'com'
        url = "https://sub3.sub2.sub1.example.com/test"
        result = inspect_url(url)

        self.assertTrue(result.is_valid)
        self.assertEqual(result.warning_count, 1)
        self.assertIn("Warning Sign 4 (Deep Subdomains)", result.warnings[0])
        self.assertIn("5 segments", result.warnings[0])

    def test_hostname_fewer_than_five_segments(self) -> None:
        """A hostname with 4 segments should NOT trigger Warning Sign 4."""
        url = "https://sub2.sub1.example.com/test"
        result = inspect_url(url)

        self.assertEqual(result.warning_count, 0)

    # -------------------------------------------------------------
    # 5. Punycode-style hostname ('xn--')
    # -------------------------------------------------------------
    def test_punycode_hostname(self) -> None:
        """A hostname containing 'xn--' triggers Warning Sign 5."""
        url = "https://xn--example.invalid/"
        result = inspect_url(url)

        self.assertTrue(result.is_valid)
        self.assertEqual(result.warning_count, 1)
        self.assertIn("Warning Sign 5 (Punycode / Homograph)", result.warnings[0])

    # -------------------------------------------------------------
    # 6. URL longer than 100 characters
    # -------------------------------------------------------------
    def test_url_longer_than_100_characters(self) -> None:
        """A URL with > 100 characters triggers Warning Sign 2."""
        # Base is 29 chars, add 80 chars -> total 109 chars (> 100)
        long_path = "a" * 80
        url = f"https://www.example.com/secure/{long_path}"
        self.assertGreater(len(url), 100)

        result = inspect_url(url)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.warning_count, 1)
        self.assertIn("Warning Sign 2 (Long URL)", result.warnings[0])

    def test_url_exactly_100_characters(self) -> None:
        """A URL with exactly 100 characters should NOT trigger length warning."""
        # Build an exact 100 character URL
        prefix = "https://www.example.com/"  # 24 chars
        filler = "x" * (100 - len(prefix))   # 76 chars
        url = prefix + filler
        self.assertEqual(len(url), 100)

        result = inspect_url(url)
        # Should NOT trigger warning 2 because length is NOT greater than 100
        length_warnings = [w for w in result.warnings if "Warning Sign 2" in w]
        self.assertEqual(len(length_warnings), 0)

    # -------------------------------------------------------------
    # 7. Empty and whitespace-only input
    # -------------------------------------------------------------
    def test_empty_string_input(self) -> None:
        """Empty input must not crash and should return is_valid=False with 0 warnings."""
        result = inspect_url("")
        self.assertFalse(result.is_valid)
        self.assertEqual(result.warning_count, 0)
        self.assertEqual(len(result.warnings), 0)
        self.assertIn("cannot be empty", result.summary)
        self.assertIsNotNone(result.error)

    def test_whitespace_only_input(self) -> None:
        """Whitespace-only input must not crash and should return is_valid=False."""
        result = inspect_url("     \t\n  ")
        self.assertFalse(result.is_valid)
        self.assertEqual(result.warning_count, 0)
        self.assertEqual(len(result.warnings), 0)
        self.assertIn("cannot be empty", result.summary)

    # -------------------------------------------------------------
    # 8. URL without a scheme (workbook convention: add http://)
    # -------------------------------------------------------------
    def test_url_without_scheme_adds_http(self) -> None:
        """A URL entered without a scheme should have http:// prepended."""
        url = "www.example.com/login"
        result = inspect_url(url)

        self.assertTrue(result.is_valid)
        self.assertEqual(result.normalized_url, "http://www.example.com/login")
        # Prepending http:// means scheme is http, triggering Sign 6 (Insecure HTTP)
        self.assertEqual(result.warning_count, 1)
        self.assertIn("Warning Sign 6 (Insecure HTTP)", result.warnings[0])

    # -------------------------------------------------------------
    # 9. Malformed URL handling
    # -------------------------------------------------------------
    def test_malformed_url_no_crash(self) -> None:
        """Malformed URL strings should be handled gracefully without crashing."""
        malformed_inputs = [
            "http://[::1:invalid-ipv6-bracket",
            "http://",
            ":///just/slashes",
        ]
        for malformed in malformed_inputs:
            with self.subTest(malformed=malformed):
                result = inspect_url(malformed)
                # Ensure the function completes and returns an InspectionResult
                self.assertIsInstance(result, InspectionResult)
                self.assertIsInstance(result.warnings, list)
                self.assertIsInstance(result.warning_count, int)
                # Verify warnings count only actual warning signs, not parsing errors
                if not result.is_valid:
                    self.assertEqual(result.warning_count, 0)

    # -------------------------------------------------------------
    # 10. URL with multiple warning signs combined
    # -------------------------------------------------------------
    def test_multiple_warning_signs_combined(self) -> None:
        """Test a URL that triggers 4 separate warning signs simultaneously:
        - Sign 1: '@' symbol
        - Sign 2: Length > 100 characters
        - Sign 3: IPv4 address hostname
        - Sign 6: Unencrypted HTTP
        """
        long_suffix = "token_param=" + ("a" * 80)
        url = f"http://admin:secret@192.0.2.10/login?{long_suffix}"
        self.assertGreater(len(url), 100)

        result = inspect_url(url)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.warning_count, 4)
        self.assertEqual(result.summary, "REVIEW CAREFULLY: 4 warning sign(s) found.")

        warnings_text = " ".join(result.warnings)
        self.assertIn("Warning Sign 1 (@ Symbol)", warnings_text)
        self.assertIn("Warning Sign 2 (Long URL)", warnings_text)
        self.assertIn("Warning Sign 3 (IPv4 Hostname)", warnings_text)
        self.assertIn("Warning Sign 6 (Insecure HTTP)", warnings_text)

    # -------------------------------------------------------------
    # 11. Workbook 5 Safe Sample Verification
    # -------------------------------------------------------------
    def test_workbook_sample_1(self) -> None:
        """Sample 1: https://www.example.com/login -> 0 warnings."""
        result = inspect_url("https://www.example.com/login")
        self.assertEqual(result.warning_count, 0)
        self.assertEqual(
            result.summary,
            "No listed warning signs found. This does NOT prove safety.",
        )

    def test_workbook_sample_2(self) -> None:
        """Sample 2: http://192.0.2.10/account -> 2 warnings (IPv4 + HTTP)."""
        result = inspect_url("http://192.0.2.10/account")
        self.assertEqual(result.warning_count, 2)
        self.assertEqual(result.summary, "REVIEW CAREFULLY: 2 warning sign(s) found.")

    def test_workbook_sample_3(self) -> None:
        """Sample 3: http://example.com@sample.invalid/login -> 2 warnings (@ + HTTP)."""
        result = inspect_url("http://example.com@sample.invalid/login")
        self.assertEqual(result.warning_count, 2)
        self.assertEqual(result.summary, "REVIEW CAREFULLY: 2 warning sign(s) found.")

    def test_workbook_sample_4(self) -> None:
        """Sample 4: https://a.b.c.d.e.example.invalid/path -> 1 warning (5+ segments)."""
        result = inspect_url("https://a.b.c.d.e.example.invalid/path")
        self.assertEqual(result.warning_count, 1)
        self.assertEqual(result.summary, "REVIEW CAREFULLY: 1 warning sign(s) found.")

    def test_workbook_sample_5(self) -> None:
        """Sample 5: https://xn--example.invalid/ -> 1 warning (punycode)."""
        result = inspect_url("https://xn--example.invalid/")
        self.assertEqual(result.warning_count, 1)
        self.assertEqual(result.summary, "REVIEW CAREFULLY: 1 warning sign(s) found.")

    # -------------------------------------------------------------
    # 12. Helper Function Tests
    # -------------------------------------------------------------
    def test_is_ipv4_address_valid(self) -> None:
        """Verify is_ipv4_address correctly identifies valid IPv4 addresses."""
        self.assertTrue(is_ipv4_address("192.0.2.10"))
        self.assertTrue(is_ipv4_address("127.0.0.1"))
        self.assertTrue(is_ipv4_address("0.0.0.0"))
        self.assertTrue(is_ipv4_address("255.255.255.255"))

    def test_is_ipv4_address_invalid(self) -> None:
        """Verify is_ipv4_address rejects invalid addresses and domain names."""
        self.assertFalse(is_ipv4_address("example.com"))
        self.assertFalse(is_ipv4_address("256.0.0.1"))        # Octet > 255
        self.assertFalse(is_ipv4_address("192.168.1"))        # Only 3 octets
        self.assertFalse(is_ipv4_address("192.168.1.1.1"))    # 5 octets
        self.assertFalse(is_ipv4_address("192.168.1.abc"))    # Non-digit
        self.assertFalse(is_ipv4_address(""))                 # Empty string

    def test_normalize_url(self) -> None:
        """Verify normalize_url prepends http:// only when scheme is absent."""
        self.assertEqual(normalize_url("example.com"), "http://example.com")
        self.assertEqual(normalize_url("https://example.com"), "https://example.com")
        self.assertEqual(normalize_url("http://example.com"), "http://example.com")
        self.assertEqual(normalize_url("ftp://example.com"), "ftp://example.com")

    def test_format_inspection_output(self) -> None:
        """Verify format_inspection_output generates required output sections."""
        res_safe = inspect_url("https://www.example.com/login")
        output_safe = format_inspection_output(res_safe)
        self.assertIn("URL Tested", output_safe)
        self.assertIn("STATUS", output_safe)
        self.assertIn("IMPORTANT SAFETY REMINDER", output_safe)

        res_warn = inspect_url("http://192.0.2.10/account")
        output_warn = format_inspection_output(res_warn)
        self.assertIn("IDENTIFIED WARNING SIGNS:", output_warn)
        self.assertIn("REVIEW CAREFULLY", output_warn)


if __name__ == "__main__":
    unittest.main()
