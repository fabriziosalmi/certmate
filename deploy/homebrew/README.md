# Homebrew

The `certmate` CLI is installable with Homebrew from the project's tap, [`fabriziosalmi/homebrew-certmate`](https://github.com/fabriziosalmi/homebrew-certmate):

```bash
brew install fabriziosalmi/certmate/certmate-cli
```

Only the client: the CertMate server runs in Docker, Kubernetes or on a Linux host.

## Where the formula lives

In the tap, at `Formula/certmate-cli.rb`, and only there. A copy in this repository could never be updated in the same pull request as a client version bump: the sha256 it needs exists only once PyPI has the new sdist.

## How it is kept current

The `bump-homebrew` job in `.github/workflows/publish-clients.yml` runs after a `clients-v*` release has published both packages to PyPI. It:

1. rewrites the formula's certmate-cli URL/sha256 and its certmate-sdk resource with `scripts/bump_homebrew_formula.py`, waiting for PyPI's index to list the version;
2. commits that locally, taps the checkout, and runs `brew install --build-from-source` and `brew test`;
3. pushes only if both pass.

It uses the `HOMEBREW_TAP_TOKEN` secret: fine-grained, Contents read/write on the tap only.

If a release adds a Python dependency, step 2 fails and nothing is pushed. Regenerate the resource blocks in a tap checkout with `brew update-python-resources fabriziosalmi/certmate/certmate-cli`, keep the `certifi` resource out (the formula depends on Homebrew's `certifi`), and push.
