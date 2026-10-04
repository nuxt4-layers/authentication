# Repository security configuration

The target configuration for `nuxt4-layers/authentication` as a public
repository that accepts outside contributions. Files in the repository carry
part of it; the rest is GitHub settings that only an admin can change, listed
here as a checklist. Re-check after any change to the organisation or a new
maintainer joining.

Threat addressed: T14 (supply-chain compromise) in [threat-model.md](threat-model.md).
The main risks of going public are a malicious pull request reaching `master`,
a pull request stealing CI secrets, a compromised dependency or Action, and a
vulnerability disclosed publicly before a fix.

## Before switching to public

| # | Check | Observed (2026-10-04) |
|---|---|---|
| P1 | History contains no secrets (scanned all 16 commits for tokens, keys, credentials) | Clean. The only credential is the disposable CI PostgreSQL password |
| P2 | Delete merged branches (`claude/charming-hopper-boizun`) | Open |
| P3 | Decide the private Theme Manager dependency: make `nuxt4-layers/theme-manager` public, or keep it private and accept that outside contributors cannot run the full suite (see CONTRIBUTING.md) | Open |
| P4 | Review open issues and pull requests: they become public too | 1 open issue |
| P5 | Rotate `NUXT4_LAYERS_READ_TOKEN` to a fine-grained token with *Contents: read* on `nuxt4-layers/theme-manager` only, with an expiry; delete it if Theme Manager becomes public | Open |

## Repository settings

**Settings → General**

- [ ] Features: Wikis off, Projects off unless used, Discussions optional.
- [ ] Pull requests: allow **squash merging** only; enable *Always suggest updating pull request branches*, *Automatically delete head branches*. Leave auto-merge off.
- [ ] *Allow forking* on (required for outside contributions; it is currently off at repository or organisation level).

**Settings → Rules → Rulesets** — one ruleset, *Active*, target the default branch (`master`), no bypass list (admins included; add yourself to bypass only for emergencies, as *pull request only*):

- [ ] Restrict deletions; block force pushes.
- [ ] Require a pull request before merging: 1 approval, *Require review from Code Owners*, *Dismiss stale approvals when new commits are pushed*, *Require approval of the most recent reviewable push*, *Require conversation resolution*. Allowed merge method: squash.
- [ ] Require status checks to pass: `quality` (and `dependency-review` once public); *Require branches to be up to date*.
- [ ] Require signed commits.
- [ ] Require linear history.
- [ ] A second ruleset on tags `v*`: restrict creation, update and deletion to admins.

While there is a single maintainer, the approval requirement blocks your own pull requests. Either add a second maintainer, or set required approvals to 0 but keep the pull-request and status-check rules (so nothing reaches `master` without green CI), and keep Code Owner review for outside contributors.

**Settings → Actions → General**

- [ ] Actions permissions: *Allow nuxt4-layers, and select non-nuxt4-layers, actions*; allow actions created by GitHub; allow `pnpm/action-setup@*`; tick *Require actions to be pinned to a full-length commit SHA*.
- [ ] *Fork pull request workflows from outside collaborators*: **Require approval for all external contributors**.
- [ ] Workflow permissions: **Read repository contents and packages permissions**; untick *Allow GitHub Actions to create and approve pull requests*.
- [ ] Artifact and log retention: 30 days or less.

**Settings → Secrets and variables → Actions**

- [ ] Only `NUXT4_LAYERS_READ_TOKEN` (see P5). No environment or organisation secrets exposed to this repository that it does not need.
- [ ] Never add a `pull_request_target` or `workflow_run` workflow that checks out pull-request code: those run with secrets and a write token.

**Settings → Advanced Security** (free for public repositories)

- [ ] Private vulnerability reporting: **on** (SECURITY.md links to it).
- [ ] Dependency graph: on. Dependabot alerts: on. Dependabot security updates: on. *Grouped security updates*: on. Dependabot version updates come from `.github/dependabot.yml`.
- [ ] Code scanning: CodeQL **default setup**, languages JavaScript/TypeScript and Actions, query suite *Extended*; add the `CodeQL` check to the ruleset once it has run.
- [ ] Secret scanning: on, with **Push protection** on. Also enable *Validity checks* and *Non-provider patterns* if offered.

**Settings → Collaborators and teams**

- [ ] Grant outside contributors no repository role: they work from forks. Give *Triage* to trusted helpers, *Write* only to maintainers.
- [ ] Organisation: require two-factor authentication for members; base permission *Read* or *No permission*; members cannot change repository visibility or delete repositories.

Moderation: use *Interaction limits* (Settings → Moderation options) if a spam wave hits.

## In the repository

| Control | File |
|---|---|
| Private reporting and response targets | `SECURITY.md`, `.github/ISSUE_TEMPLATE/config.yml` |
| Contributor workflow and dependency rules | `CONTRIBUTING.md`, `.github/pull_request_template.md` |
| Code owner review for every path | `.github/CODEOWNERS` |
| Actions pinned to full commit SHAs; workflow token read-only; checkout without persisted credentials | `.github/workflows/*.yml` |
| Read token confined to the install step (throwaway Git config, removed before the pull request's code runs); no `pull_request_target` | `.github/workflows/quality.yml` |
| Dependency and licence review on pull requests (public repositories) | `.github/workflows/dependency-review.yml` |
| Weekly Dependabot updates for npm and Actions with a 7-day cooldown | `.github/dependabot.yml` |
| Install scripts only for allow-listed packages; versions at least a day old; registry-only transitive dependencies; frozen lockfile in CI | `pnpm-workspace.yaml`, `.github/workflows/quality.yml` |
