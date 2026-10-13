from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List


@dataclass
class Finding:
    category: str
    message: str
    line_no: int
    severity: str
    score: int


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)

    @property
    def total_score(self) -> int:
        return sum(item.score for item in self.findings)

    @property
    def risk_level(self) -> str:
        score = self.total_score
        if score >= 16:
            return "Critical"
        if score >= 10:
            return "High"
        if score >= 5:
            return "Medium"
        return "Low"

    @property
    def summary(self) -> str:
        return f"{len(self.findings)} finding(s) | risk score {self.total_score} | {self.risk_level}"


PATTERNS: Iterable[tuple[str, str, re.Pattern[str], int]] = (
    (
        "Command execution",
        "Windows command execution pattern detected",
        re.compile(r"(?i)\b(powershell|cmd\.exe|rundll32|mshta|wscript|cscript|regsvr32|certutil|bitsadmin)\b"),
        4,
    ),
    (
        "Remote download",
        "Potential payload download or script fetch detected",
        re.compile(r"(?i)(curl\s+https?://|wget\s+https?://|Invoke-WebRequest|Start-BitsTransfer|GET\s+https?://|POST\s+https?://)"),
        5,
    ),
    (
        "Encoded payload",
        "Encoded content or payload obfuscation detected",
        re.compile(r"(?i)(base64\s*-?e|FromBase64String|System\.Net\.WebClient|IEX\s*\()"),
        6,
    ),
    (
        "Credential exposure",
        "Possible password, token, or API key exposure",
        re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password|passwd)\b\s*[:=]\s*['\"]?[A-Za-z0-9!@#$%^&*._-]{6,}"),
        6,
    ),
    (
        "Suspicious domain",
        "Reference to a potentially malicious domain",
        re.compile(r"(?i)https?://[A-Za-z0-9.-]+\.(?:ru|cn|xyz|top|club|online|bid)"),
        3,
    ),
    (
        "Suspicious file",
        "Executable or script file path associated with malware behavior",
        re.compile(r"(?i)\b(?:[A-Za-z]:\\|/)?(?:.*\\|/)?[A-Za-z0-9._-]+\.(?:exe|dll|ps1|vbs|js|jar)\b"),
        3,
    ),
)


def scan_text(text: str) -> ScanResult:
    findings: List[Finding] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for category, message, pattern, score in PATTERNS:
            if pattern.search(line):
                severity = "High" if score >= 5 else "Medium" if score >= 3 else "Low"
                findings.append(
                    Finding(
                        category=category,
                        message=message,
                        line_no=line_no,
                        severity=severity,
                        score=score,
                    )
                )
    return ScanResult(findings=findings)


def scan_file(path: str | Path) -> ScanResult:
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8", errors="replace")
    return scan_text(text)
