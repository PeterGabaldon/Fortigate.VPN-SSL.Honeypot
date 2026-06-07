## 2024-06-07 - Jinja2 Template Autoescape Configuration
**Vulnerability:** XSS vulnerability in template rendering due to missing autoescape configuration for `.jinja` file extensions in `select_autoescape`.
**Learning:** `select_autoescape(["html", "xml"])` does not cover files ending with `.html.jinja`. Variables injected into these files were entirely unescaped, allowing for cross-site scripting attacks or HTML injection in email reports and alerts.
**Prevention:** Always ensure all template file extensions used in the project are explicitly added to the `select_autoescape` list, particularly when dealing with custom or chained extensions like `.html.jinja`.
