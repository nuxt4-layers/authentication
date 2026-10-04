# Contributing

Thank you for helping. This layer handles authentication, so changes are
reviewed with security first. Read [CLAUDE.md](CLAUDE.md) for the project rules
and [docs/threat-model.md](docs/threat-model.md) before changing server code.

## Workflow

1. Fork the repository and branch from `master`.
2. Make a focused change with tests. Run `pnpm check`; run the database and
   end-to-end suites if you touched server code or pages (see the README).
3. Open a pull request. A maintainer approves CI for first-time contributors;
   every pull request needs a code owner's review and a green Quality check
   before it is merged.

Commits to `master` must be signed. Sign yours with
[SSH or GPG](https://docs.github.com/authentication/managing-commit-signature-verification),
or a maintainer will squash-merge (GitHub signs the merge commit).

## Private Theme Manager dependency

The playground and the end-to-end suite compose Theme Manager, which is
currently a private repository. Until it is public, contributors without
access to `nuxt4-layers/theme-manager` cannot run `pnpm install` from the
lockfile, and CI on pull requests from forks cannot fetch it (forks receive no
secrets), so the Quality check on your pull request will fail at that step.
A maintainer reviews the change first and then runs the full suite for you.

## Dependencies

Add a dependency only when necessary, and say why in the pull request. New
dependencies must be maintained, MIT-compatible and free of install scripts
(pnpm runs install scripts only for packages listed in `pnpm-workspace.yaml`).
Always commit `pnpm-lock.yaml`.

## Security issues

Never in public issues or pull requests: see [SECURITY.md](SECURITY.md).
