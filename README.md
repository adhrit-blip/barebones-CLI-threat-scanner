# CyberSec Threat Scanner

A lightweight cybersecurity project for scanning text logs and suspicious script content for common indicators of malicious activity.

## Features

- Detects command execution patterns like PowerShell and CMD abuse
- Flags remote downloads and script-fetch commands
- Spots encoded payloads and base64 obfuscation tactics
- Identifies possible credential exposure
- Checks for suspicious domains and executable file names
- Produces a simple risk score and severity level

## Quick start

From the cloned project directory, scan a file with:

```bash
python main.py suspicious.log
```

Or read log text from standard input:

```bash
python main.py --stdin < suspicious.log
```

## Run with Docker

If Docker is installed, build the image from this directory:

```bash
docker build -t cybersec-threat-scanner .
```

Then scan a local log file (mount it read-only):

```bash
docker run --rm -v "C:\path\to\suspicious.log:/data/suspicious.log:ro" cybersec-threat-scanner /data/suspicious.log
```

The scanner uses only the Python standard library, so no extra Python packages are needed.

If you want to test it with a sample file, create a text file such as `sample.log` and include suspicious indicators like:

```text
powershell -enc JABjAG8AbgBzAG8AbABlAHMA
GET http://malware.example.ru/loader.exe
password=admin123
```

## Example output

```text
Risk level: High
Summary: 5 finding(s) | risk score 22 | High
- [High] Line 2: Command execution -> Windows command execution pattern detected
- [Medium] Line 3: Suspicious domain -> Reference to a potentially malicious domain
```

## Run tests

From the project directory:

```bash
python -m unittest discover -s tests -v
```

## Why I made it

This project is designed for learning and awareness. It is not a replacement for enterprise SIEM, EDR, or malware analysis tools.

@adhrit-blip