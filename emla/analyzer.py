import re
from typing import List, Dict, Tuple
from emla.models import Finding, FindingCategory, Severity, ErrorResponse

class ResponseAnalyzer:
    """Analyzes error responses (headers and body) for sensitive information disclosure."""

    # Pre-compiled regex patterns categorized by leakage type
    PATTERNS: List[Dict[str, any]] = [
        # --- STACK TRACES ---
        {
            "category": FindingCategory.STACK_TRACE,
            "severity": Severity.CRITICAL,
            "title": "Python Stack Trace Disclosed",
            "regex": re.compile(r"Traceback\s+\(most\s+recent\s+call\s+last\):", re.IGNORECASE),
            "detail": "Python traceback detected in response body."
        },
        {
            "category": FindingCategory.STACK_TRACE,
            "severity": Severity.CRITICAL,
            "title": "Java Stack Trace Disclosed",
            "regex": re.compile(r"\bat\s+[a-zA-Z0-9_.]+\.[a-zA-Z0-9_]+\(([a-zA-Z0-9_]+\.java:\d+|\bNative\s+Method\b|\bUnknown\s+Source\b)\)"),
            "detail": "Java exception stack trace detected in response body."
        },
        {
            "category": FindingCategory.STACK_TRACE,
            "severity": Severity.CRITICAL,
            "title": "PHP Exception / Stack Trace Disclosed",
            "regex": re.compile(r"(Fatal\s+error|Parse\s+error|Uncaught\s+Exception|Stack\s+trace:)\s*:\s*", re.IGNORECASE),
            "detail": "PHP error or uncaught exception stack trace disclosed."
        },
        {
            "category": FindingCategory.STACK_TRACE,
            "severity": Severity.CRITICAL,
            "title": "Node.js Stack Trace Disclosed",
            "regex": re.compile(r"\b[a-zA-Z0-9_]*Error:\s+.*\n\s*at\s+.*(?:\([^)]+:\d+:\d+\)|:\d+:\d+)"),
            "detail": "Node.js execution call stack disclosed."
        },
        {
            "category": FindingCategory.STACK_TRACE,
            "severity": Severity.CRITICAL,
            "title": ".NET / C# Stack Trace Disclosed",
            "regex": re.compile(r"(\bat\s+.*in\s+.*:line\s+\d+|System\.[a-zA-Z0-9_.]+Exception:)"),
            "detail": ".NET framework exception call stack disclosed."
        },

        # --- DATABASE ERRORS ---
        {
            "category": FindingCategory.DATABASE_ERROR,
            "severity": Severity.HIGH,
            "title": "MySQL / MariaDB Error Disclosed",
            "regex": re.compile(r"(You\s+have\s+an\s+error\s+in\s+your\s+SQL\s+syntax|MySQL\s+server\s+version\s+for\s+the\s+right\s+syntax|SQLSTATE\[\d+\])", re.IGNORECASE),
            "detail": "MySQL database engine syntax error or message exposed."
        },
        {
            "category": FindingCategory.DATABASE_ERROR,
            "severity": Severity.HIGH,
            "title": "PostgreSQL Error Disclosed",
            "regex": re.compile(r"(ERROR:\s+syntax\s+error\s+at\s+or\s+near|PG::SyntaxError:|org\.postgresql\.util\.PSQLException)", re.IGNORECASE),
            "detail": "PostgreSQL database exception or query syntax error exposed."
        },
        {
            "category": FindingCategory.DATABASE_ERROR,
            "severity": Severity.HIGH,
            "title": "SQLite Error Disclosed",
            "regex": re.compile(r"(SQLite3::SQLException|sqlite3\.OperationalError:|\[SQLite\s+error\])", re.IGNORECASE),
            "detail": "SQLite database exception disclosed in response."
        },
        {
            "category": FindingCategory.DATABASE_ERROR,
            "severity": Severity.HIGH,
            "title": "Oracle DB Error Disclosed",
            "regex": re.compile(r"\bORA-\d{5}:", re.IGNORECASE),
            "detail": "Oracle Database error code (ORA-XXXXX) disclosed."
        },
        {
            "category": FindingCategory.DATABASE_ERROR,
            "severity": Severity.HIGH,
            "title": "MSSQL / ODBC Error Disclosed",
            "regex": re.compile(r"(Driver.*SQL\s+Server|OLE\s+DB.*SQL\s+Server|Unclosed\s+quotation\s+mark\s+after\s+the\s+character\s+string)", re.IGNORECASE),
            "detail": "Microsoft SQL Server database exception disclosed."
        },

        # --- FRAMEWORK DISCLOSURES ---
        {
            "category": FindingCategory.FRAMEWORK_VERSION,
            "severity": Severity.HIGH,
            "title": "Django Debug Mode Active",
            "regex": re.compile(r"You're\s+seeing\s+this\s+error\s+because\s+you\s+have\s+<code>DEBUG\s*=\s*True</code>", re.IGNORECASE),
            "detail": "Django development debug mode is enabled, revealing sensitive internal state."
        },
        {
            "category": FindingCategory.FRAMEWORK_VERSION,
            "severity": Severity.HIGH,
            "title": "Flask / Werkzeug Debugger Exposed",
            "regex": re.compile(r"(Werkzeug\s+powered\s+traceback|Debugger\040PIN)", re.IGNORECASE),
            "detail": "Werkzeug debug page detected in response."
        },
        {
            "category": FindingCategory.FRAMEWORK_VERSION,
            "severity": Severity.HIGH,
            "title": "Laravel Ignition Debug Screen Exposed",
            "regex": re.compile(r"(Spatie\\LaravelIgnition|laravel-ignition)", re.IGNORECASE),
            "detail": "Laravel Ignition error handler page exposed."
        },
        {
            "category": FindingCategory.FRAMEWORK_VERSION,
            "severity": Severity.MEDIUM,
            "title": "Spring Boot Whitelabel Error Disclosed",
            "regex": re.compile(r"Whitelabel\s+Error\s+Page", re.IGNORECASE),
            "detail": "Spring Boot default Whitelabel error page exposed."
        },

        # --- FILESYSTEM PATHS ---
        {
            "category": FindingCategory.FILESYSTEM_PATH,
            "severity": Severity.HIGH,
            "title": "UNIX System File Path Disclosed",
            "regex": re.compile(r"(?:/(?:var|home|usr|etc|opt|tmp|app|srv|root)/[a-zA-Z0-9._/-]+)", re.IGNORECASE),
            "detail": "Internal UNIX server filesystem path disclosed in response body."
        },
        {
            "category": FindingCategory.FILESYSTEM_PATH,
            "severity": Severity.HIGH,
            "title": "Windows System File Path Disclosed",
            "regex": re.compile(r"[a-zA-Z]:\\(?:[a-zA-Z0-9_.-]+\\)+[a-zA-Z0-9_.-]+"),
            "detail": "Internal Windows filesystem directory or path disclosed in response body."
        }
    ]

    # Header inspection rules
    HEADER_RULES = [
        {
            "header": "server",
            "category": FindingCategory.RUNTIME_SERVER,
            "severity": Severity.LOW,
            "title": "Detailed Server Header Disclosed",
            "detail": "The 'Server' header exposes specific server version information."
        },
        {
            "header": "x-powered-by",
            "category": FindingCategory.RUNTIME_SERVER,
            "severity": Severity.LOW,
            "title": "X-Powered-By Header Disclosed",
            "detail": "The 'X-Powered-By' header exposes underlying technology software stack."
        },
        {
            "header": "x-aspnet-version",
            "category": FindingCategory.FRAMEWORK_VERSION,
            "severity": Severity.LOW,
            "title": "X-AspNet-Version Header Disclosed",
            "detail": "The 'X-AspNet-Version' header exposes ASP.NET framework version."
        }
    ]

    def analyze_response(self, response: ErrorResponse) -> List[Finding]:
        """Runs all pattern matchers and header inspectors against an ErrorResponse."""
        findings: List[Finding] = []
        seen_titles = set()

        # 1. Inspect Response Body against regex patterns
        for rule in self.PATTERNS:
            match = rule["regex"].search(response.body)
            if match:
                title = rule["title"]
                if title not in seen_titles:
                    seen_titles.add(title)
                    snippet = match.group(0)[:150]  # Limit snippet length
                    findings.append(
                        Finding(
                            category=rule["category"],
                            severity=rule["severity"],
                            title=title,
                            detail=rule["detail"],
                            snippet=snippet
                        )
                    )

        # 2. Inspect Headers for software disclosure
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        for rule in self.HEADER_RULES:
            header_name = rule["header"]
            if header_name in headers_lower:
                header_val = headers_lower[header_name]
                # Flag if header reveals version numbers (e.g. Apache/2.4.41 vs just Apache)
                title = rule["title"]
                if title not in seen_titles:
                    seen_titles.add(title)
                    findings.append(
                        Finding(
                            category=rule["category"],
                            severity=rule["severity"],
                            title=title,
                            detail=f"{rule['detail']} (Value: {header_val})",
                            snippet=f"{header_name}: {header_val}"
                        )
                    )

        return findings
