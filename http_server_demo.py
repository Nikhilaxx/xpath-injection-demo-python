# http_server_demo.py
# Simple HTTP server for demonstrating XPath Injection (vulnerable) vs safe fixed approach.
# Requires: Python 3.x (no external libraries)
#
# Usage:
# 1. Put users.xml in the same folder (same users.xml you have).
# 2. Run: python http_server_demo.py
# 3. Open http://localhost:8000  (vulnerable demo)
#    Open http://localhost:8000/fixed (safe demo)

from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse as urlparse
import xml.etree.ElementTree as ET
import html
import re

HOST = 'localhost'
PORT = 8000
XML_FILE = "users.xml"

BASE_HTML = """<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>XPath Demo - {title}</title>
    <style>
      body {{ font-family: Arial, sans-serif; padding: 20px; }}
      .container {{ max-width: 820px; margin: auto; }}
      .box {{ border: 1px solid #ddd; padding: 12px; border-radius: 6px; margin-bottom: 12px; }}
      pre {{ background:#f6f6f6; padding:8px; border-radius:4px; overflow:auto; white-space:pre-wrap; }}
      .links a {{ margin-right: 12px; }}
    </style>
  </head>
  <body>
    <div class="container">
      <h1>XPath Demo — {title}</h1>
      <div class="links">
        <a href="/">Vulnerable demo</a>
        <a href="/fixed">Fixed demo</a>
      </div>
      <div class="box">
        <form method="POST" action="{action}">
          <label>Username to search: <input name="username" /></label>
          <input type="submit" value="Search" />
        </form>
      </div>
      <div class="box">
        <h3>Output</h3>
        <pre>{output}</pre>
      </div>
      <div style="font-size:0.9em; color:#555;">
        <p><strong>Note:</strong> The vulnerable demo constructs an XPath from raw input and executes it .</p>
        
      </div>
    </div>
  </body>
</html>
"""

def build_xpath_for_display(username_input):
    """Return an ElementTree-compatible XPath string or None if cannot safely build because input contains both quotes."""
    if "'" in username_input and '"' in username_input:
        return None
    if "'" in username_input:
        return './/user[username="%s"]' % username_input
    else:
        return ".//user[username='%s']" % username_input

def run_vulnerable_xpath(username):
    """Builds and executes an XPath from raw input (vulnerable pattern)."""
    try:
        tree = ET.parse(XML_FILE)
        root = tree.getroot()
    except Exception as e:
        return f"ERROR: Failed to read XML file: {e}"

    xpath = build_xpath_for_display(username)
    if xpath is None:
        return ("DEBUG: cannot construct a simple ElementTree-compatible XPath "
                "(input contains both single and double quotes). Try a normal username like 'bob' or 'alice'.")
    debug = f"DEBUG: constructed xpath -> {xpath}\n\n"
    try:
        results = root.findall(xpath)
    except SyntaxError as e:
        return debug + f"ERROR: XPath syntax error: {e}"
    except Exception as e:
        return debug + f"ERROR: XPath execution failed: {e}"

    if not results:
        return debug + f"No matching user found for: {html.escape(username)}"
    out_lines = [debug]
    for u in results:
        uname = u.findtext("username")
        role = u.findtext("role")
        email = u.findtext("email")
        out_lines.append(f"Found user -> username: {html.escape(uname)}, role: {html.escape(role)}, email: {html.escape(email)}")
    return "\n".join(out_lines)

def run_fixed_search(username_input):
    """Safe search: validate input, then iterate elements and compare exact text."""
    # Basic normalization + length check
    username = username_input.strip()
    if not username:
        return "Input rejected: empty username."
    if len(username) > 64:
        return "Input rejected: username too long."

    # Whitelist-ish check: allow only letters, numbers, dash, underscore, dot
    if not re.fullmatch(r"[A-Za-z0-9\-\_\.]+", username):
        return "Input rejected: username contains disallowed characters."

    try:
        tree = ET.parse(XML_FILE)
        root = tree.getroot()
    except Exception as e:
        return f"ERROR: Failed to read XML file: {e}"

    found = []
    for u in root.findall(".//user"):
        uname = u.findtext("username")
        if uname == username:
            found.append((u.findtext("username"), u.findtext("role"), u.findtext("email")))

    if not found:
        return f"No matching user found for: {html.escape(username)}"
    lines = ["Search succeeded (safe exact-match)."]
    for uname, role, email in found:
        lines.append(f"Found user -> username: {html.escape(uname)}, role: {html.escape(role)}, email: {html.escape(email)}")
    return "\n".join(lines)

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split('?',1)[0]
        if path == "/" or path == "/index.html":
            self._serve_page(title="Vulnerable (builds XPath from input)", action="/vulnerable", output="")
        elif path == "/fixed":
            self._serve_page(title="Fixed (safe search)", action="/fixed_search", output="")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not found")

    def do_POST(self):
        path = self.path.split('?',1)[0]
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8')
        params = urlparse.parse_qs(body)
        username = params.get('username', [''])[0]

        if path == "/vulnerable":
            output = run_vulnerable_xpath(username)
            self._serve_page(title="Vulnerable (builds XPath from input)", action="/vulnerable", output=html.escape(output))
        elif path == "/fixed_search":
            output = run_fixed_search(username)
            self._serve_page(title="Fixed (safe search)", action="/fixed_search", output=html.escape(output))
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not found")

    def _serve_page(self, title, action, output):
        html_body = BASE_HTML.format(title=html.escape(title),
                                     action=html.escape(action),
                                     output=output)
        body_bytes = html_body.encode('utf-8')
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)

if __name__ == "__main__":
    print(f"Starting server at http://{HOST}:{PORT}  (Ctrl+C to stop)")
    server = HTTPServer((HOST, PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
        server.server_close()
