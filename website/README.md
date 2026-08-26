# ShipProof public site

This is a static, dependency-free public surface for ShipProof. It intentionally has no analytics, API calls, source upload, or build step.

From the repository root, preview it locally:

```bash
python -m http.server 4173
```

Then open [http://127.0.0.1:4173/website/](http://127.0.0.1:4173/website/).

The Thai locale is available at [http://127.0.0.1:4173/website/index.th.html](http://127.0.0.1:4173/website/index.th.html); the header language switch links both locales without a runtime translation service.

The site reuses the checked-in assets in `docs/assets/`. Keep the scanner, CLI, Action, and MCP contracts authoritative; update copy when the product contract changes.
