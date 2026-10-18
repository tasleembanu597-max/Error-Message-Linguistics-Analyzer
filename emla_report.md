# 🛡️ EMLA Multi-Target Security Summary Report

- **Scan Date**: `2026-10-10T13:59:32.394412+00:00`
- **Total Targets Scanned**: 4
- **Highest Target Risk Score**: **`44.6`** / 100.0 (HIGH)
- **Total Endpoints Scanned**: 53
- **Total Findings**: 124
- **Duration**: 1.233s

## 🎯 Target Overview

| Target URL | Score | Rating | Endpoints | Findings |
| :--- | :--- | :--- | :--- | :--- |
| [http://127.0.0.1:53188](http://127.0.0.1:53188) | **0.0** | NONE | 1 | 0 |
| [http://127.0.0.1:53790](http://127.0.0.1:53790) | **0.0** | NONE | 1 | 0 |
| [http://127.0.0.1:22](http://127.0.0.1:22) | **0.0** | NONE | 1 | 0 |
| [http://127.0.0.1:8000](http://127.0.0.1:8000) | **44.6** | HIGH | 50 | 124 |

---

# 🛡️ EMLA Security Report - http://127.0.0.1:53188

- **Scan Date**: `2026-10-10T13:59:32.394671+00:00`
- **Overall Risk Score**: **`0.0`** / 100.0 (NONE)
- **Total Endpoints Scanned**: 1
- **Total Findings**: 0
- **Duration**: 0.004s

## 📊 Severity Breakdown

| Severity | Count |
| :--- | :--- |
| **CRITICAL** | 0 |
| **HIGH** | 0 |
| **MEDIUM** | 0 |
| **LOW** | 0 |
| **INFO** | 0 |

## 📡 Scanned Endpoints & Vulnerabilities

### `[GET]` [http://127.0.0.1:53188](http://127.0.0.1:53188)
- **Status Code**: `500` | **Score**: `0.0`
- ✅ *No information leakage detected on this endpoint.*

---
# 🛡️ EMLA Security Report - http://127.0.0.1:53790

- **Scan Date**: `2026-10-10T13:59:32.395487+00:00`
- **Overall Risk Score**: **`0.0`** / 100.0 (NONE)
- **Total Endpoints Scanned**: 1
- **Total Findings**: 0
- **Duration**: 0.018s

## 📊 Severity Breakdown

| Severity | Count |
| :--- | :--- |
| **CRITICAL** | 0 |
| **HIGH** | 0 |
| **MEDIUM** | 0 |
| **LOW** | 0 |
| **INFO** | 0 |

## 📡 Scanned Endpoints & Vulnerabilities

### `[GET]` [http://127.0.0.1:53790](http://127.0.0.1:53790)
- **Status Code**: `500` | **Score**: `0.0`
- ✅ *No information leakage detected on this endpoint.*

---
# 🛡️ EMLA Security Report - http://127.0.0.1:22

- **Scan Date**: `2026-10-10T13:59:32.395262+00:00`
- **Overall Risk Score**: **`0.0`** / 100.0 (NONE)
- **Total Endpoints Scanned**: 1
- **Total Findings**: 0
- **Duration**: 0.237s

## 📊 Severity Breakdown

| Severity | Count |
| :--- | :--- |
| **CRITICAL** | 0 |
| **HIGH** | 0 |
| **MEDIUM** | 0 |
| **LOW** | 0 |
| **INFO** | 0 |

## 📡 Scanned Endpoints & Vulnerabilities

### `[GET]` [http://127.0.0.1:22](http://127.0.0.1:22)
- **Status Code**: `500` | **Score**: `0.0`
- ✅ *No information leakage detected on this endpoint.*

---
# 🛡️ EMLA Security Report - http://127.0.0.1:8000

- **Scan Date**: `2026-10-10T13:59:32.395068+00:00`
- **Overall Risk Score**: **`44.6`** / 100.0 (HIGH)
- **Total Endpoints Scanned**: 50
- **Total Findings**: 124
- **Duration**: 1.232s

## 📊 Severity Breakdown

| Severity | Count |
| :--- | :--- |
| **CRITICAL** | 12 |
| **HIGH** | 12 |
| **MEDIUM** | 0 |
| **LOW** | 100 |
| **INFO** | 0 |

## 📡 Scanned Endpoints & Vulnerabilities

### `[GET]` [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Status Code**: `200` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/.git](http://127.0.0.1:8000/.git)
- **Status Code**: `200` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/.pytest_cache](http://127.0.0.1:8000/.pytest_cache)
- **Status Code**: `200` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/emla](http://127.0.0.1:8000/emla)
- **Status Code**: `200` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/emla.egg-info](http://127.0.0.1:8000/emla.egg-info)
- **Status Code**: `200` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/emla_report.csv](http://127.0.0.1:8000/emla_report.csv)
- **Status Code**: `200` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/emla_report.html](http://127.0.0.1:8000/emla_report.html)
- **Status Code**: `200` | **Score**: `59.5`

**Findings:**

- **[CRITICAL]** `STACK_TRACE` - **Python Stack Trace Disclosed**: Python traceback detected in response body.
  ```text
  Traceback (most recent call last):
  ```
- **[CRITICAL]** `STACK_TRACE` - **PHP Exception / Stack Trace Disclosed**: PHP error or uncaught exception stack trace disclosed.
  ```text
  Fatal error: 
  ```
- **[HIGH]** `DATABASE_ERROR` - **MySQL / MariaDB Error Disclosed**: MySQL database engine syntax error or message exposed.
  ```text
  You have an error in your SQL syntax
  ```
- **[HIGH]** `FILESYSTEM_PATH` - **UNIX System File Path Disclosed**: Internal UNIX server filesystem path disclosed in response body.
  ```text
  /var/www/html/login.php
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/emla_report.json](http://127.0.0.1:8000/emla_report.json)
- **Status Code**: `200` | **Score**: `59.5`

**Findings:**

- **[CRITICAL]** `STACK_TRACE` - **Python Stack Trace Disclosed**: Python traceback detected in response body.
  ```text
  Traceback (most recent call last):
  ```
- **[CRITICAL]** `STACK_TRACE` - **PHP Exception / Stack Trace Disclosed**: PHP error or uncaught exception stack trace disclosed.
  ```text
  Fatal error: 
  ```
- **[HIGH]** `DATABASE_ERROR` - **MySQL / MariaDB Error Disclosed**: MySQL database engine syntax error or message exposed.
  ```text
  You have an error in your SQL syntax
  ```
- **[HIGH]** `FILESYSTEM_PATH` - **UNIX System File Path Disclosed**: Internal UNIX server filesystem path disclosed in response body.
  ```text
  /var/www/html/login.php
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/emla_report.md](http://127.0.0.1:8000/emla_report.md)
- **Status Code**: `200` | **Score**: `59.5`

**Findings:**

- **[CRITICAL]** `STACK_TRACE` - **Python Stack Trace Disclosed**: Python traceback detected in response body.
  ```text
  Traceback (most recent call last):
  ```
- **[CRITICAL]** `STACK_TRACE` - **PHP Exception / Stack Trace Disclosed**: PHP error or uncaught exception stack trace disclosed.
  ```text
  Fatal error: 
  
  ```
- **[HIGH]** `DATABASE_ERROR` - **MySQL / MariaDB Error Disclosed**: MySQL database engine syntax error or message exposed.
  ```text
  You have an error in your SQL syntax
  ```
- **[HIGH]** `FILESYSTEM_PATH` - **UNIX System File Path Disclosed**: Internal UNIX server filesystem path disclosed in response body.
  ```text
  /var/www/html/login.php
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/emla_report.txt](http://127.0.0.1:8000/emla_report.txt)
- **Status Code**: `200` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/emla_report.xml](http://127.0.0.1:8000/emla_report.xml)
- **Status Code**: `200` | **Score**: `59.5`

**Findings:**

- **[CRITICAL]** `STACK_TRACE` - **Python Stack Trace Disclosed**: Python traceback detected in response body.
  ```text
  Traceback (most recent call last):
  ```
- **[CRITICAL]** `STACK_TRACE` - **PHP Exception / Stack Trace Disclosed**: PHP error or uncaught exception stack trace disclosed.
  ```text
  Fatal error: 
  ```
- **[HIGH]** `DATABASE_ERROR` - **MySQL / MariaDB Error Disclosed**: MySQL database engine syntax error or message exposed.
  ```text
  You have an error in your SQL syntax
  ```
- **[HIGH]** `FILESYSTEM_PATH` - **UNIX System File Path Disclosed**: Internal UNIX server filesystem path disclosed in response body.
  ```text
  /var/www/html/login.php
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/generate_e2e_report.py](http://127.0.0.1:8000/generate_e2e_report.py)
- **Status Code**: `200` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/README.md](http://127.0.0.1:8000/README.md)
- **Status Code**: `200` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/report.html](http://127.0.0.1:8000/report.html)
- **Status Code**: `200` | **Score**: `59.5`

**Findings:**

- **[CRITICAL]** `STACK_TRACE` - **Python Stack Trace Disclosed**: Python traceback detected in response body.
  ```text
  Traceback (most recent call last):
  ```
- **[CRITICAL]** `STACK_TRACE` - **PHP Exception / Stack Trace Disclosed**: PHP error or uncaught exception stack trace disclosed.
  ```text
  Fatal error: 
  ```
- **[HIGH]** `DATABASE_ERROR` - **MySQL / MariaDB Error Disclosed**: MySQL database engine syntax error or message exposed.
  ```text
  You have an error in your SQL syntax
  ```
- **[HIGH]** `FILESYSTEM_PATH` - **UNIX System File Path Disclosed**: Internal UNIX server filesystem path disclosed in response body.
  ```text
  /var/www/html/login.php
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/report.json](http://127.0.0.1:8000/report.json)
- **Status Code**: `200` | **Score**: `59.5`

**Findings:**

- **[CRITICAL]** `STACK_TRACE` - **Python Stack Trace Disclosed**: Python traceback detected in response body.
  ```text
  Traceback (most recent call last):
  ```
- **[CRITICAL]** `STACK_TRACE` - **PHP Exception / Stack Trace Disclosed**: PHP error or uncaught exception stack trace disclosed.
  ```text
  Fatal error: 
  ```
- **[HIGH]** `DATABASE_ERROR` - **MySQL / MariaDB Error Disclosed**: MySQL database engine syntax error or message exposed.
  ```text
  You have an error in your SQL syntax
  ```
- **[HIGH]** `FILESYSTEM_PATH` - **UNIX System File Path Disclosed**: Internal UNIX server filesystem path disclosed in response body.
  ```text
  /var/www/html/login.php
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/requirements.txt](http://127.0.0.1:8000/requirements.txt)
- **Status Code**: `200` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/run_tests.ipynb](http://127.0.0.1:8000/run_tests.ipynb)
- **Status Code**: `200` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/setup.py](http://127.0.0.1:8000/setup.py)
- **Status Code**: `200` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/sf_Share](http://127.0.0.1:8000/sf_Share)
- **Status Code**: `200` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/tests](http://127.0.0.1:8000/tests)
- **Status Code**: `200` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/venv](http://127.0.0.1:8000/venv)
- **Status Code**: `200` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/COMMIT_EDITMSG](http://127.0.0.1:8000/COMMIT_EDITMSG)
- **Status Code**: `404` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/config](http://127.0.0.1:8000/config)
- **Status Code**: `404` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/description](http://127.0.0.1:8000/description)
- **Status Code**: `404` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/HEAD](http://127.0.0.1:8000/HEAD)
- **Status Code**: `404` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/hooks](http://127.0.0.1:8000/hooks)
- **Status Code**: `404` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/index](http://127.0.0.1:8000/index)
- **Status Code**: `404` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/info](http://127.0.0.1:8000/info)
- **Status Code**: `404` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/logs](http://127.0.0.1:8000/logs)
- **Status Code**: `404` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/objects](http://127.0.0.1:8000/objects)
- **Status Code**: `404` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/refs](http://127.0.0.1:8000/refs)
- **Status Code**: `404` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/.gitignore](http://127.0.0.1:8000/.gitignore)
- **Status Code**: `404` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/CACHEDIR.TAG](http://127.0.0.1:8000/CACHEDIR.TAG)
- **Status Code**: `404` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/v](http://127.0.0.1:8000/v)
- **Status Code**: `404` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/__init__.py](http://127.0.0.1:8000/__init__.py)
- **Status Code**: `404` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/__pycache__](http://127.0.0.1:8000/__pycache__)
- **Status Code**: `404` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/analyzer.py](http://127.0.0.1:8000/analyzer.py)
- **Status Code**: `404` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/cli.py](http://127.0.0.1:8000/cli.py)
- **Status Code**: `404` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/crawler.py](http://127.0.0.1:8000/crawler.py)
- **Status Code**: `404` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/engine.py](http://127.0.0.1:8000/engine.py)
- **Status Code**: `404` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/models.py](http://127.0.0.1:8000/models.py)
- **Status Code**: `404` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/reporter.py](http://127.0.0.1:8000/reporter.py)
- **Status Code**: `404` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/scoring.py](http://127.0.0.1:8000/scoring.py)
- **Status Code**: `404` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/trigger.py](http://127.0.0.1:8000/trigger.py)
- **Status Code**: `404` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/ui.py](http://127.0.0.1:8000/ui.py)
- **Status Code**: `404` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/dependency_links.txt](http://127.0.0.1:8000/dependency_links.txt)
- **Status Code**: `404` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/entry_points.txt](http://127.0.0.1:8000/entry_points.txt)
- **Status Code**: `404` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/PKG-INFO](http://127.0.0.1:8000/PKG-INFO)
- **Status Code**: `404` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/requires.txt](http://127.0.0.1:8000/requires.txt)
- **Status Code**: `404` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---
### `[GET]` [http://127.0.0.1:8000/SOURCES.txt](http://127.0.0.1:8000/SOURCES.txt)
- **Status Code**: `404` | **Score**: `3.0`

**Findings:**

- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
- **[LOW]** `RUNTIME_SERVER` - **Detailed Server Header Disclosed**: The 'Server' header exposes specific server version information. (Value: SimpleHTTP/0.6 Python/3.13.12)
  ```text
  server: SimpleHTTP/0.6 Python/3.13.12
  ```
---