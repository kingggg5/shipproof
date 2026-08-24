# Versioned command contracts

These normalized JSON reports are both golden output fixtures and backward-compatibility exemplars for schema version `1.0`. Absolute roots are replaced with `<ROOT>` and artifact paths inside the checkout with `<PACKAGE_ROOT>/...`; all other fields and values remain exact.

`tests/node/command-contracts.test.mjs` executes every public evidence command through the Node CLI and compares the complete normalized report. `tests/test_command_contracts.py` validates the same snapshots against the current command-specific schemas. Removing or renaming a field therefore requires an explicit schema-version and compatibility decision instead of a silent snapshot update.

Regenerate deliberately after a reviewed contract change:

```bash
UPDATE_SHIPPROOF_COMMAND_CONTRACTS=1 node tests/node/command-contracts.test.mjs
```

Never update these fixtures only to make CI green; review the semantic diff and exit-code behavior first.
