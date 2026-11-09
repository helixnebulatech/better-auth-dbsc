# Contributing

## Setup

```sh
bun install
bun run build
bun run test          # Vitest on Node and edge-runtime
bun run check-types   # tsrs
bun run check         # Ultracite (oxlint + oxfmt); `bun run fix` to fix
bun run publint
```

The Chromium end-to-end tests drive a real browser through registration, refresh and a stolen-cookie replay (see [Local testing](./docs/local-testing.md)):

```sh
cd packages/better-auth-dbsc
bun x playwright install chromium
bun run test:e2e
```

Conventions are in [`AGENTS.md`](./AGENTS.md). User documentation lives in [`docs/`](./docs); update it with any change to behaviour or options.

## Dependencies

- Dev dependencies are pinned to exact versions. Runtime and peer dependencies use `^` ranges with the latest version as the floor, so apps can share one copy of `@noble/*` and Better Auth.
- `bunfig.toml` sets `minimumReleaseAge` to 2 days: Bun does not install versions younger than that. Dependabot uses the same cooldown.
- GitHub Actions are pinned to commit SHAs.

## Changesets

Every pull request that changes the published package (`packages/better-auth-dbsc`, outside tests and `e2e/`) needs a changeset:

```sh
bun run changeset
```

Use `patch` for fixes and additions, `minor` for breaking changes while the package is `0.x`.

## Releases

Releases run in `.github/workflows/release.yml`, with the same model as Better Auth and the Vercel AI SDK:

- **npm Trusted Publishing.** npm accepts an OIDC token from this repository, this workflow and the `Release` environment, and nothing else. No npm token exists anywhere, and every version gets a provenance attestation.
- **Split jobs.** `version` opens or updates the "chore: release" pull request and cannot publish. `pack` builds, tests and packs the tarballs, and also cannot publish. Only `publish` holds `id-token: write`. It runs in the `Release` environment, does not build, and installs dependencies without lifecycle scripts.
- **Hardened workflows.** Permissions default to none and each job adds only what it needs. Credentials are not persisted, release jobs use no caches, and zizmor checks every workflow change.

Flow: merge pull requests with changesets into `main`. The workflow opens the release pull request. Merging that pull request publishes to npm and creates the git tag and GitHub release.

### One-time setup

1. **GitHub → Settings → Actions → General.** Enable "Allow GitHub Actions to create and approve pull requests".
2. **GitHub → Settings → Environments.** Create `Release`:
   - Under "Deployment branches and tags", select "Selected branches and tags" and add `main` only.
   - Optional: add yourself under "Required reviewers". Each publish then waits for your approval.
3. **npm.** npm can only configure a Trusted Publisher for a package that already exists, so the first version is published by hand. Do it from an empty folder, outside the repository:

   ```sh
   mkdir better-auth-dbsc-placeholder && cd better-auth-dbsc-placeholder
   echo '{ "name": "better-auth-dbsc", "version": "0.0.0" }' > package.json
   npm publish
   ```

   On `https://www.npmjs.com/package/better-auth-dbsc/access`:
   - Under **Trusted Publisher**, choose GitHub Actions and fill in organization `helixnebulatech`, repository `better-auth-dbsc`, workflow `release.yml` and environment `Release`. Never leave the environment empty: that would allow publishing from any branch.
   - Under **Publishing access**, select "Require two-factor authentication and disallow tokens". From then on, only the workflow can publish.
   - After the first real release, deprecate the placeholder: `npm deprecate better-auth-dbsc@0.0.0 "Placeholder, use a later version"`.

4. **GitHub → Settings → Branches.** Protect `main`: require pull requests and the CI checks to pass.
5. **GitHub → Settings → Code security.** Enable "Private vulnerability reporting", which [SECURITY.md](./SECURITY.md) relies on.
