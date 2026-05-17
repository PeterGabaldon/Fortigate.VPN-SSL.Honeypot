## 2024-05-17 - SQL Injection in Shell Scripts and Reflected XSS in Flask

**Vulnerability:** SQL Injection in `parse.sh` and Reflected XSS in `honey/honey.py`. The bash script `parse.sh` unsafely interpolated variables parsed from log files (`ip` and `ts`) directly into a SQLite command. `honey.py` included `request.path` directly in a 404 response without HTML escaping.
**Learning:** Even when reading from log files, input must be treated as untrusted and properly sanitized. Single quotes must be escaped in SQL queries built dynamically in shell scripts. Similarly, user input like the request path must be HTML-escaped before embedding it in HTML responses, even in custom error pages.
**Prevention:** Always use `str.replace` (or equivalent shell construct like `${var//"'"/''}`) to escape single quotes when constructing SQL queries manually in bash scripts. For XSS, always use `html.escape()` or a template engine like Jinja2 that auto-escapes by default.
