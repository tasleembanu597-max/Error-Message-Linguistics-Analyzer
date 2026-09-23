# Test Results

## Test Environment

- Operating System: Kali Linux
- Target: http://localhost
- Tool: Error Message Linguistics Analyzer (EMLA)
- Mode: Single URL Scan

## Test Execution

The EMLA tool was executed against the local Apache web server.

## Results

- Total endpoints scanned: 1
- Total findings: 4
- Overall risk score: 18.29 / 100
- Overall severity: MEDIUM:
- ## Severity Breakdown

- HIGH: 2
- LOW: 2

## Findings

1. UNIX System File Path Disclosed
   - Category: FILESYSTEM_PATH
   - Severity: HIGH
   - Example: /var/www/html/index.html

2. Detailed Server Header Disclosed
   - Category: RUNTIME_SERVER
   - Severity: LOW
   - Example: Apache/2.4.68 (Debian)

## Report

The EMLA tool successfully generated a JSON report containing the scan results and findings.
report containing the scan results and findings 
