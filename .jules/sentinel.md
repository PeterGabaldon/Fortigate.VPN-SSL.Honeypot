## 2024-06-07 - Jinja2 Template Autoescape Configuration
**Vulnerability:** XSS vulnerability in template rendering due to missing autoescape configuration for `.jinja` file extensions in `select_autoescape`.
**Learning:** `select_autoescape(["html", "xml"])` does not cover files ending with `.html.jinja`. Variables injected into these files were entirely unescaped, allowing for cross-site scripting attacks or HTML injection in email reports and alerts.
**Prevention:** Always ensure all template file extensions used in the project are explicitly added to the `select_autoescape` list, particularly when dealing with custom or chained extensions like `.html.jinja`.

## 2026-06-28 - [URL Encoding Sanitization Bypass]
**Vulnerability:** Application failed to URL-decode incoming credentials before passing them to sanitization and logging logic.
**Learning:** Bypassing security checks like AD lockout rate-limiting and counter-intelligence scanning became possible because an attacker could send URL-encoded inputs (e.g., %61dmin instead of admin) creating distinct DB entries for the same target user while bypassing string filters.
**Prevention:** Inputs from the web must be normalized/decoded (e.g., using urllib.parse.unquote_plus) to their intended raw form before any sanitization, filtering, or business logic is applied. Additionally, null byte (\x00) injection protections should be explicitly applied when decoding raw user data.
