# Automated tests

The Python policy engine is covered by standard-library `unittest` tests.
Fixtures in `fixtures/` model secure and insecure normalized Compose JSON, so
these tests do not need Docker Compose, a Docker Engine, or external Python
packages. `fixtures/compose/` also contains small insecure Compose overrides
for manually exercising the scanner CLI; scanning them uses Compose
configuration normalization only and does not start containers or pull images.

From the repository root, run:

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
```

For VS Code Git Bash on Windows, `py -3.11` can be used instead of `python`:

```sh
PYTHONPATH=src py -3.11 -m unittest discover -s tests -v
```

Keep manual infrastructure verification scripts in `scripts/verify/`.
