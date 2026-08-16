# Release guide

Publishing is intentionally human-gated. CI validates the exact package contents, but the repository does not publish merely because a branch changed.

Pushing a protected tag that exactly matches `package.json` (for example `v0.4.0`) runs the GitHub Release workflow. It repeats the complete verification suite, validates the matching checked-in release-note file, builds the npm tarball, smoke-tests the packed artifact end to end, and creates a prerelease for every `0.x` version. `gh release create --verify-tag` prevents the workflow from inventing a missing remote tag. Registry publication remains a separate, explicitly approved step.

## Tag discipline

- Exact version tags (`v0.5.1`) are immutable once pushed; never force-push them.
- The Release workflow also maintains a moving major tag (`v0` today) that is force-updated to the latest reviewed release of that major. It is a convenience alias, not a stability contract; consumers who need immutability must pin the exact version tag or a full commit SHA.
- A moving `v1` tag ships only with the stable v1 compatibility contract described in the roadmap.

## Pre-release

1. Update `package.json`, both plugin manifests, scanner metadata, tests, and `CHANGELOG.md` to the same version.
2. Run `npm ci --ignore-scripts`, install `requirements-dev.txt`, run `npm run check`, Python compile checks, and the local scanner.
3. Inspect `npm pack --dry-run`; verify only the allowlisted files are included and no secret, fixture, report, or development cache is present.
4. Review dependency, CodeQL, SARIF, and branch-protection results.
5. Create a signed or protected tag only from the reviewed commit.
6. Push the tag, confirm the Release workflow, and inspect the attached tarball before promoting or publishing it elsewhere.

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
