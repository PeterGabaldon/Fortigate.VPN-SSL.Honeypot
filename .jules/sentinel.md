## 2025-05-24 - [Fix] Add autoescaping to Jinja2 Environment in check_ldap.py
**Vulnerability:** XSS / HTML Injection in HTML email generation. The `check_ldap.py` script constructed an email template rendering the captured honeypot credentials using `jinja2.Environment` without the `autoescape` option.
**Learning:** Automatically rendering user-provided or unverified data in templates (even within email bodies) requires autoescaping to prevent malicious payload execution or display manipulation, especially when attackers deliberately provide input like HTML tags inside username/password fields to phish or inject content.
**Prevention:** Always initialize Jinja2 `Environment` with `autoescape=select_autoescape(["html", "xml"])` to sanitize output securely.
