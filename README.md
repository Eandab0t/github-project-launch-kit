# GitHub Project Launch Kit

A small CLI that prepares a folder or repo for GitHub: checks, warnings and a
launch checklist. No AI, no telemetry, no plugins, no config files.
Dry-run by default.

## Run it

**Windows (PowerShell):**
```powershell
.\launch-kit.ps1                          # dry-run checks on the current folder
.\launch-kit.ps1 -Path C:\code\myrepo     # check another folder
.\launch-kit.ps1 -Apply                   # enable GitHub guards + write LAUNCH-CHECKLIST.md
```

**Linux / macOS / Git Bash:**
```bash
./launch-kit.sh                           # dry-run checks on the current folder
./launch-kit.sh --path /srv/code/myrepo   # check another folder
./launch-kit.sh --apply                   # enable GitHub guards + write LAUNCH-CHECKLIST.md
```

`--dry-run` / `-DryRun` are also accepted explicitly, but dry-run is already
the default.

## What it checks

| Section | Detail |
|---|---|
| Repository | Is the folder a Git repository? |
| Project files | README, LICENSE (or COPYING), .gitignore, project metadata (package.json, pyproject.toml, go.mod, Cargo.toml, *.csproj, ...) |
| Secrets & personal paths | Private key blocks, AWS keys, GitHub/Slack/OpenAI/Google tokens, credential-style assignments, exposed `.env`, personal absolute paths (`C:\Users\...`, `E:\...`, `/home/...`, `/Users/...`) |
| GitHub protections | Branch rules, Dependabot alerts, secret push protection — via the `gh` CLI |
| Launch checklist | Printed every run; written to `LAUNCH-CHECKLIST.md` with `-Apply` |

In a git repo only **tracked** files are scanned (that is what would get
published); in a plain folder everything except `.git`, `node_modules`,
build/venv directories and obvious binaries is scanned.

## Dry-run by default

Nothing is changed unless you pass `-Apply` / `--apply`. And even then the
tool only:

- enables the same three guards as `gh-guard` (identical ruleset name and
  payloads, so the two tools skip each other's rules — safe to re-run either),
- writes `LAUNCH-CHECKLIST.md` (never overwrites an existing one).

It never deletes files, never force-pushes, never changes remotes and never
publishes anything.

## GitHub protections

| Guard | Effect |
|---|---|
| `protect-default-branch` ruleset | Force-push and default-branch deletion blocked for everyone, including you |
| Dependabot alerts | Email alerts for vulnerable dependencies |
| Secret push protection | Pushes containing API keys/tokens are rejected |

Same plan limitation as gh-guard: branch rules on **private** repos need
GitHub Pro; on the free plan they apply to public repos. The tool reports
`plan-limited` instead of failing.

Without the `gh` CLI, or without a GitHub `origin` remote, the tool prints
the manual Settings toggles instead of doing nothing silently.

## Output

Small sections, `+` / `!` / `x` symbols for success / warning / error.
Colors are used only when the terminal supports them and `NO_COLOR` is unset.

```
GitHub Project Launch Kit
folder : C:\code\myrepo
mode   : dry run (nothing will be changed)

== Repository ==
[+] Git repository detected

== Project files ==
[+] README: README.md
[!] LICENSE not found
...
```

## Exit codes

- `0` — ready (warnings allowed)
- `1` — not a Git repository, or likely secrets were found in tracked files

## Tests

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests\run-tests.ps1
bash tests/run-tests.sh
```

Hand-rolled asserts over temp-dir fixtures — no test framework, no
dependencies, mirroring the zero-dependency style of `..\gh-guard`.

## Requirements

- `git`
- `gh` CLI (optional, only for GitHub protections): https://cli.github.com
- PowerShell 5.1+ / bash 4.1+

## Related

`..\gh-guard` applies the same three GitHub guards to any repo you own.
This tool checks a folder *before* launch; gh-guard hardens repos *after*.
