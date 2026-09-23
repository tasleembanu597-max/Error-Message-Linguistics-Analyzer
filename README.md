# Error Message Linguistics Analyzer

A cybersecurity tool that analyzes error messages from web applications and identifies potential information leakage and security-related findings.

## Features
- Analyzes HTTP error responses
- Detects information leakage
- Identifies exposed file paths
- Detects server information disclosure
- Assigns severity levels
- Generates a JSON report

## Technology
- Python
- Web/HTTP analysis
- JSON reporting

## Usage
Run the tool from the command line and provide the target URL for analysis.


## Test Results

The project was tested in Kali Linux against a local Apache web server.

- Target: http://localhost
- Mode: Single URL Scan
- Endpoints scanned: 1
- Total findings: 4
- Overall risk score: 18.29 / 100
- Overall severity: MEDIUM
- High severity findings: 2
- Low severity findings: 2

The tool successfully generated a JSON report containing the scan results and findings.

## Project Files

- analyzer.py - Error message analysis
- crawler.py - Web crawling
- engine.py - Main scanning engine
- models.py - Data models
- reporter.py - JSON report generation
- scoring.py - Risk scoring
- trigger.py - Finding detection
- cli.py - Command-line interface
