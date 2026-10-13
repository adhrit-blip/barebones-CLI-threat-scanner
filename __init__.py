"""Cybersecurity log analyzer project."""

from .scanner import ScanResult, scan_file, scan_text

__all__ = ["ScanResult", "scan_file", "scan_text"]
