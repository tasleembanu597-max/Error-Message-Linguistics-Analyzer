import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

class MockAppHandler(BaseHTTPRequestHandler):
    """Local HTTP handler simulating a web application with intentional error disclosure."""

    def log_message(self, format, *args):
        # Silence HTTP server stdout logging during test runs
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            html = """
            <html>
                <body>
                    <h1>Mock App</h1>
                    <a href="/about">About Us</a>
                    <a href="/search?q=test">Search</a>
                    <a href="/logout">Logout</a>
                    <form action="/login" method="POST">
                        <input name="username" type="text" />
                        <input name="password" type="password" />
                        <button type="submit">Login</button>
                    </form>
                </body>
            </html>
            """
            self.wfile.write(html.encode("utf-8"))

        elif parsed.path == "/about":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
            self.end_headers()
            self.wfile.write(b"<html><body>About page</body></html>")

        elif parsed.path == "/search":
            if "EMLA_INVALID_TYPE" in str(params.get("q", [])):
                self.send_response(500)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                body = "Traceback (most recent call last):\n  File \"/app/search.py\", line 15\nTypeError: expected string"
                self.wfile.write(body.encode("utf-8"))
            elif "' OR 1=1" in str(params.get("q", [])):
                self.send_response(500)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                body = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
                self.wfile.write(body.encode("utf-8"))
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body>Search results</body></html>")

        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>404 Not Found</body></html>")

    def do_POST(self):
        parsed = urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else ""

        if parsed.path == "/login":
            if "EMLA_INVALID_TYPE" in post_body or "' OR 1=1" in post_body:
                self.send_response(500)
                self.send_header("Content-Type", "text/html")
                self.send_header("X-Powered-By", "PHP/7.4.3")
                self.end_headers()
                body = "Fatal error: Uncaught Error in /var/www/html/login.php:42\nStack trace:\n#0 {main}"
                self.wfile.write(body.encode("utf-8"))
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body>Login successful</body></html>")
        else:
            self.send_response(405)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>405 Method Not Allowed</body></html>")

class MockServerThread:
    """Thread context manager to run the mock HTTP server locally on port 8888."""

    def __init__(self, host="127.0.0.1", port=8888):
        self.server = HTTPServer((host, port), MockAppHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.base_url = f"http://{host}:{port}"

    def start(self):
        self.thread.start()
        time.sleep(0.1)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
