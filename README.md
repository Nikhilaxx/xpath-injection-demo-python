# Implementation and Prevention of XPath Injection Attacks Using Python

## Project overview

This repository contains a safe, local demonstration of **XPath Injection** and a secure implementation that prevents it. The demo is implemented in pure Python (no external packages required) and runs as a lightweight local HTTP server. It is intended for educational and ethical use only — do **not** run on public-facing servers or use production data.

**Key goals:**
- Demonstrate how unsafe construction of XPath queries from user input can expose data.
- Provide a secure alternative using input validation and exact-match logic.
- Offer detection and mitigation guidance for learning and reporting purposes.

---

## Files in this repo

- `title.jpg` — optional front-page image used for presentation materials.  
- `users.xml` — sample XML dataset (3 user records).  
- `http_server_demo.py` — main demo server with:
  - `GET /` & `POST /vulnerable` — vulnerable endpoint (prints constructed XPath for demonstration).
  - `GET /fixed` & `POST /fixed_search` — secure endpoint (validated, safe search).  
- `vuln_xpath_demo.py` — simple terminal vulnerable demo (optional).  
- `fix_iterative.py` — safe terminal demo (optional).  
- `README.md` — this file.  
- `.gitignore` — recommended ignore rules.

---

## Prerequisites

- Python 3.6+ installed (tested with Python 3.11)
- A web browser (Chrome/Firefox/Edge) for the demo
- No external Python packages required

---

## Quick start — run the demo

-1. Clone the repo and change directory:
```bash
git clone <your-repo-url>
cd xpath-injection-demo-python
Ensure users.xml and http_server_demo.py are in the same folder.

-Run the server:
-python3 http_server_demo.py
-Open the following pages in your browser:

-Vulnerable demo: http://localhost:8000

-Fixed demo: http://localhost:8000/fixed
