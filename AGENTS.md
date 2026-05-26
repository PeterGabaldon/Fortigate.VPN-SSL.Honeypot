# Repository Guidelines

## Project Structure & Module Organization

- `honey/` contains the Flask honeypot app, Dockerfile, static CSS/JS, fonts, and login-page assets.
- `nginx/` contains the Nginx Dockerfile and runtime configuration, including TLS helper scripts under `nginx/dist/conf/ssl/`.
- `parse.py` reads honeypot and Nginx logs, stores events in SQLite, and writes parsed outputs.
- `report_to_email/`, `report_to_otx/`, `report_to_vt/`, `report_to_abuseipdb/`, and `check_in_ldap/` are standalone helper scripts with their own `requirements.txt` and config templates.
- `payload*.json`, `screenshot.png`, and `icon.png` are sample/documentation assets.

## Build, Test, and Development Commands

- `docker compose up --build`: builds and starts Nginx and the honeypot locally.
- `docker compose down -v`: stops containers and removes compose-managed volumes.
- `cd nginx/dist/conf/ssl && ./gen-cert.sh && ./gen-dhparam.sh 2048`: generates local TLS material before building from source.
- `python3 -m compileall -q -f .`: byte-compiles Python files and catches syntax errors.
- `flake8 . --select=E9,F63,F7,F82 --show-source --statistics`: runs the same syntax-only flake8 checks used in CI.
- `./parse.py`: parses configured log files into SQLite and output reports.
- Do not write Python unit tests, this project does not use them.

Install dependencies per component, for example:

```bash
cd report_to_email
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## Coding Style & Naming Conventions

Use Python 3.10+ compatible code. Follow PEP 8: 4-space indentation, `snake_case` for functions and variables, and uppercase constants such as `DB_FILE`. Keep integration scripts self-contained and prefer config paths or environment variables over hard-coded local paths. Preserve directory patterns such as `report_to_<service>/`.

## Testing Guidelines

There is no dedicated unit test suite. Before opening a PR, run the syntax checks above and, when Docker files change, verify `docker compose up --build` succeeds. For parser or reporter changes, test with copied sample logs or config templates. Do not commit generated databases, logs, secrets, or virtual environments.

## Commit & Pull Request Guidelines

Recent history uses short imperative messages, often Conventional Commit style, for example `fix: Add missing llm_summary...` or `refactor: Migrate LLM summary...`. Prefer `fix:`, `feat:`, `refactor:`, or `docs:` prefixes when applicable.

Do not open pull requests or work in dev branches, commit and push directly in the current working branch. If the current selected git branch is "main" commit and push to it, if it is "dev" commit and push directly to it...

## Security & Configuration Tips

Never commit API keys, SMTP or LDAP credentials, generated TLS private keys, SQLite databases, or production logs. Start from `*.template` config files and keep real configs local. If using Docker Hub images, review the README warning about bundled TLS material and replace it for deployment.
