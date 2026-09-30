import pytest
from emla.models import ErrorResponse, FindingCategory, Severity
from emla.analyzer import ResponseAnalyzer

@pytest.fixture
def analyzer():
    return ResponseAnalyzer()

# --- 1. STACK TRACES TESTS ---
def test_python_stack_trace_detection(analyzer):
    body = """
    Internal Server Error:
    Traceback (most recent call last):
      File "/app/views.py", line 42, in get
        result = 1 / 0
    ZeroDivisionError: division by zero
    """
    resp = ErrorResponse(url="http://localhost/test", status_code=500, headers={}, body=body)
    findings = analyzer.analyze_response(resp)

    assert len(findings) == 2  # Python Stack Trace + UNIX File Path (/app/views.py)
    categories = [f.category for f in findings]
    assert FindingCategory.STACK_TRACE in categories
    assert FindingCategory.FILESYSTEM_PATH in categories

def test_java_stack_trace_detection(analyzer):
    body = "Exception in thread 'main' java.lang.NullPointerException\n\tat com.example.myproject.Book.getTitle(Book.java:16)"
    resp = ErrorResponse(url="http://localhost/api", status_code=500, headers={}, body=body)
    findings = analyzer.analyze_response(resp)

    assert len(findings) >= 1
    assert any(f.category == FindingCategory.STACK_TRACE and "Java" in f.title for f in findings)

def test_php_stack_trace_detection(analyzer):
    body = "Fatal error: Uncaught Error: Call to undefined function foo() in /var/www/html/index.php:12\nStack trace:\n#0 {main}"
    resp = ErrorResponse(url="http://localhost/index.php", status_code=500, headers={}, body=body)
    findings = analyzer.analyze_response(resp)

    assert len(findings) >= 1
    assert any(f.category == FindingCategory.STACK_TRACE and "PHP" in f.title for f in findings)

def test_nodejs_stack_trace_detection(analyzer):
    body = "Error: Connection refused\n    at TCPConnectWrap.afterConnect [as oncomplete] (net.js:1146:16)"
    resp = ErrorResponse(url="http://localhost/node", status_code=500, headers={}, body=body)
    findings = analyzer.analyze_response(resp)

    assert len(findings) >= 1
    assert any(f.category == FindingCategory.STACK_TRACE and "Node.js" in f.title for f in findings)

def test_dotnet_stack_trace_detection(analyzer):
    body = "System.NullReferenceException: Object reference not set to an instance of an object.\n   at App.Controllers.HomeController.Index() in C:\\App\\Controllers\\HomeController.cs:line 25"
    resp = ErrorResponse(url="http://localhost/dotnet", status_code=500, headers={}, body=body)
    findings = analyzer.analyze_response(resp)

    assert len(findings) >= 1
    assert any(f.category == FindingCategory.STACK_TRACE and ".NET" in f.title for f in findings)


# --- 2. DATABASE ERRORS TESTS ---
def test_mysql_error_detection(analyzer):
    body = "Uncaught Exception: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
    resp = ErrorResponse(url="http://localhost/db", status_code=500, headers={}, body=body)
    findings = analyzer.analyze_response(resp)

    assert any(f.category == FindingCategory.DATABASE_ERROR and "MySQL" in f.title for f in findings)

def test_postgres_error_detection(analyzer):
    body = "ERROR: syntax error at or near \"SELECT\" at character 1"
    resp = ErrorResponse(url="http://localhost/pg", status_code=500, headers={}, body=body)
    findings = analyzer.analyze_response(resp)

    assert any(f.category == FindingCategory.DATABASE_ERROR and "PostgreSQL" in f.title for f in findings)

def test_sqlite_error_detection(analyzer):
    body = "sqlite3.OperationalError: no such table: users"
    resp = ErrorResponse(url="http://localhost/sqlite", status_code=500, headers={}, body=body)
    findings = analyzer.analyze_response(resp)

    assert any(f.category == FindingCategory.DATABASE_ERROR and "SQLite" in f.title for f in findings)

def test_oracle_error_detection(analyzer):
    body = "ORA-00942: table or view does not exist"
    resp = ErrorResponse(url="http://localhost/ora", status_code=500, headers={}, body=body)
    findings = analyzer.analyze_response(resp)

    assert any(f.category == FindingCategory.DATABASE_ERROR and "Oracle" in f.title for f in findings)

def test_mssql_error_detection(analyzer):
    body = "Microsoft OLE DB Provider for SQL Server error '80040e14' Unclosed quotation mark after the character string"
    resp = ErrorResponse(url="http://localhost/mssql", status_code=500, headers={}, body=body)
    findings = analyzer.analyze_response(resp)

    assert any(f.category == FindingCategory.DATABASE_ERROR and "MSSQL" in f.title for f in findings)


# --- 3. FRAMEWORK DISCLOSURES TESTS ---
def test_django_debug_mode_detection(analyzer):
    body = "<h1>DisallowedHost</h1><p>You're seeing this error because you have <code>DEBUG = True</code> in your Django settings file.</p>"
    resp = ErrorResponse(url="http://localhost/django", status_code=500, headers={}, body=body)
    findings = analyzer.analyze_response(resp)

    assert any(f.category == FindingCategory.FRAMEWORK_VERSION and "Django" in f.title for f in findings)

def test_flask_werkzeug_debugger_detection(analyzer):
    body = "<html><body><h1>Werkzeug powered traceback</h1><div class=\"pin-prompt\">Debugger PIN</div></body></html>"
    resp = ErrorResponse(url="http://localhost/flask", status_code=500, headers={}, body=body)
    findings = analyzer.analyze_response(resp)

    assert any(f.category == FindingCategory.FRAMEWORK_VERSION and "Werkzeug" in f.title for f in findings)

def test_laravel_ignition_detection(analyzer):
    body = "<script>window.ignition = Spatie\\LaravelIgnition</script>"
    resp = ErrorResponse(url="http://localhost/laravel", status_code=500, headers={}, body=body)
    findings = analyzer.analyze_response(resp)

    assert any(f.category == FindingCategory.FRAMEWORK_VERSION and "Laravel" in f.title for f in findings)


# --- 4. FILESYSTEM PATHS TESTS ---
def test_unix_path_detection(analyzer):
    body = "Failed to load configuration file at /var/www/config/settings.yaml"
    resp = ErrorResponse(url="http://localhost/path", status_code=500, headers={}, body=body)
    findings = analyzer.analyze_response(resp)

    assert any(f.category == FindingCategory.FILESYSTEM_PATH and "UNIX" in f.title for f in findings)

def test_windows_path_detection(analyzer):
    body = "Could not find file 'C:\\inetpub\\wwwroot\\app\\web.config'."
    resp = ErrorResponse(url="http://localhost/winpath", status_code=500, headers={}, body=body)
    findings = analyzer.analyze_response(resp)

    assert any(f.category == FindingCategory.FILESYSTEM_PATH and "Windows" in f.title for f in findings)


# --- 5. HEADER DISCLOSURES TESTS ---
def test_headers_disclosure_detection(analyzer):
    headers = {
        "Server": "Apache/2.4.41 (Ubuntu)",
        "X-Powered-By": "PHP/7.4.3",
        "X-AspNet-Version": "4.0.30319"
    }
    resp = ErrorResponse(url="http://localhost/headers", status_code=200, headers=headers, body="Hello World")
    findings = analyzer.analyze_response(resp)

    assert len(findings) == 3
    titles = [f.title for f in findings]
    assert "Detailed Server Header Disclosed" in titles
    assert "X-Powered-By Header Disclosed" in titles
    assert "X-AspNet-Version Header Disclosed" in titles


# --- 6. NEGATIVE CASES (NO FINDINGS) ---
def test_clean_response_no_findings(analyzer):
    body = "<html><head><title>Welcome</title></head><body><h1>Hello World</h1><p>Normal response text.</p></body></html>"
    headers = {"Content-Type": "text/html"}
    resp = ErrorResponse(url="http://localhost/clean", status_code=200, headers=headers, body=body)
    findings = analyzer.analyze_response(resp)

    assert len(findings) == 0

def test_generic_500_error_no_findings(analyzer):
    body = "<html><body><h1>500 Internal Server Error</h1><p>An unexpected error occurred. Please try again later or contact support.</p></body></html>"
    headers = {"Content-Type": "text/html"}
    resp = ErrorResponse(url="http://localhost/500", status_code=500, headers=headers, body=body)
    findings = analyzer.analyze_response(resp)

    assert len(findings) == 0


# --- 7. DUPED FINDINGS HANDLING ---
def test_duplicate_findings_deduplicated(analyzer):
    body = """
    Traceback (most recent call last):
      File "/app/test.py", line 1
    Traceback (most recent call last):
      File "/app/test.py", line 10
    """
    resp = ErrorResponse(url="http://localhost/dupes", status_code=500, headers={}, body=body)
    findings = analyzer.analyze_response(resp)

    # Should only contain 1 Python Stack Trace finding and 1 UNIX path finding
    python_trace_findings = [f for f in findings if f.title == "Python Stack Trace Disclosed"]
    assert len(python_trace_findings) == 1
