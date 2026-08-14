# Release guide

Publishing is intentionally human-gated. CI validates the exact package contents, but the repository does not publish merely because a branch changed.

## Pre-release

1. Update `package.json`, both plugin manifests, scanner metadata, tests, and `CHANGELOG.md` to the same version.
2. Run `npm ci --ignore-scripts`, `npm run check`, Python compile checks, and the local scanner.
3. Inspect `npm pack --dry-run`; verify only the allowlisted files are included and no secret, fixture, report, or development cache is present.
4. Review dependency, CodeQL, SARIF, and branch-protection results.
5. Create a signed or protected tag only from the reviewed commit.

## npm trusted publishing

The first release requires the package owner to create the scoped package and configure the GitHub workflow as an npm trusted publisher. Prefer OIDC trusted publishing over a long-lived `NPM_TOKEN`. Restrict the trusted publisher to the exact repository, workflow filename, and protected environment.

For the strongest human gate, configure staged publishing where available and require a maintainer to approve promotion with 2FA. After trusted publishing works, disallow traditional publish tokens.

Required release-workflow controls:

- GitHub-hosted runner and `contents: read`, `id-token: write` only for the publish job.
- Clean `npm ci --ignore-scripts` because ShipProof has no external dependencies or install scripts.
- Full tests and `npm pack --dry-run` before `npm publish`.
- Public repository and exact `repository.url` so npm can attach provenance.
- Protected environment/tag and manual review before registry publication.

Do not add an automated publish workflow until the registry package and trusted-publisher relationship exist; otherwise every release would fail or tempt maintainers to add a long-lived token.

Primary guidance: [npm trusted publishers](https://docs.npmjs.com/trusted-publishers/) and [npm provenance](https://docs.npmjs.com/generating-provenance-statements/).
