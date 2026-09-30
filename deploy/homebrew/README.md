# Homebrew formula for certmate-cli

`certmate-cli.rb` installs the CertMate command-line client (`certmate`) into its own virtualenv, with Homebrew's Python. Only the client: the server does not belong on Homebrew.

It was verified with a local tap: `brew install --build-from-source` succeeds, `certmate health` reads a live instance, `brew test` passes, and `brew audit --strict --online` reports nothing.

## Publishing it

The tap is [`fabriziosalmi/homebrew-certmate`](https://github.com/fabriziosalmi/homebrew-certmate), one tap per project as for proxxx and flareover. This file is copied there as `Formula/certmate-cli.rb`, and users run:

```bash
brew install fabriziosalmi/certmate/certmate-cli
```

## Updating it

When a new certmate-cli or certmate-sdk is published to PyPI, update `url`/`sha256` (and the `certmate-sdk` resource), then regenerate the dependency blocks from a tap checkout:

```bash
brew update-python-resources fabriziosalmi/certmate/certmate-cli
```

Keep the `certifi` resource out: the formula depends on Homebrew's `certifi` instead. `tests/test_the_homebrew_formula.py` fails when this file and the client versions in `clients/` disagree.
