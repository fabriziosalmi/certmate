# Contributing to CertMate

Contributions are welcome. Open a pull request at any time.

## How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-change`)
3. Commit your changes (`git commit -m 'Add my change'`)
4. Push to the branch (`git push origin feature/my-change`)
5. Open a Pull Request

## Development Setup

```bash
git clone https://github.com/fabriziosalmi/certmate.git
cd certmate
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-test.txt   # dev + test tooling (pytest, flake8, black, isort, bandit)
python app.py
```

## Running Tests

```bash
python -m pytest tests/ -v
```

> **Editing templates/CSS?** CI gates a fresh Tailwind bundle and the theme tokens.
> Run `npm ci && npm run css:build` and commit `static/css/tailwind.min.css`, and
> avoid raw `*-600 dark:*-400` colour pairs (use the semantic tokens).

## Code Style

- Follow existing code conventions
- Keep commits focused and descriptive
- Add tests for new functionality when possible

## Reporting Issues

Open an issue on GitHub with:
- Steps to reproduce
- Expected vs. actual behavior
- CertMate version and environment details
