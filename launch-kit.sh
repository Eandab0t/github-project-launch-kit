#!/usr/bin/env bash
# launch-kit - prepare a folder for its GitHub launch. Dry-run by default.
#
# Checks:
#   1. Is this folder a Git repository?
#   2. README / LICENSE / .gitignore / project metadata present?
#   3. Likely secrets and personal absolute paths in tracked files?
#   4. GitHub protections (branch rules, Dependabot, secret push protection):
#      enabled via the gh CLI with --apply, or explained for manual setup.
#   5. Prints a launch checklist; --apply also writes LAUNCH-CHECKLIST.md.
#
# Usage:
#   launch-kit.sh                  dry-run checks on the current folder
#   launch-kit.sh --path DIR       check another folder
#   launch-kit.sh --apply          enable GitHub guards + write the checklist
#
# Dry-run by default. Never deletes files, never force-pushes, never touches
# remotes, never publishes anything. Guard payloads mirror gh-guard exactly.
# Requires: git. Optional: gh CLI (only used for the GitHub guards).
# bash 4.1+ recommended (case-insensitive matching of some secret patterns).

set -u

TARGET="."
APPLY=0

BRANCH_JSON='{"name":"protect-default-branch","target":"branch","enforcement":"active","conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]}},"bypass_actors":[],"rules":[{"type":"deletion"},{"type":"non_fast_forward"}]}'
SECRET_JSON='{"security_and_analysis":{"secret_scanning_push_protection":{"status":"enabled"}}}'

# --- output -------------------------------------------------------------------

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'; C_SEC=$'\033[36m'; C_OFF=$'\033[0m'
else
    C_OK=""; C_WARN=""; C_ERR=""; C_SEC=""; C_OFF=""
fi

ok()      { printf '%s[+]%s %s\n' "$C_OK" "$C_OFF" "$1"; }
warn()    { printf '%s[!]%s %s\n' "$C_WARN" "$C_OFF" "$1"; }
err()     { printf '%s[x]%s %s\n' "$C_ERR" "$C_OFF" "$1"; }
section() { printf '\n%s== %s ==%s\n' "$C_SEC" "$1" "$C_OFF"; }

usage() {
    printf 'Usage: launch-kit.sh [--path DIR] [--apply] [--dry-run]\n' >&2
    exit 1
}

# --- checks -------------------------------------------------------------------

is_git_repo() { [ -e "$1/.git" ]; }

find_project_files() {
    F_README=""; F_LICENSE=""; F_GITIGNORE=""; F_METADATA=""
    local f b lower
    while IFS= read -r -d '' f; do
        b=${f##*/}
        lower=$(printf '%s' "$b" | tr '[:upper:]' '[:lower:]')
        case $lower in
            readme*)                    [ -z "$F_README" ]  && F_README=$b ;;
            license*|licence*|copying*) [ -z "$F_LICENSE" ] && F_LICENSE=$b ;;
        esac
        if [ "$lower" = ".gitignore" ] && [ -z "$F_GITIGNORE" ]; then F_GITIGNORE=$b; fi
        if [ -z "$F_METADATA" ]; then
            case $lower in
                package.json|pyproject.toml|setup.py|setup.cfg|requirements.txt|cargo.toml|go.mod|pom.xml|build.gradle|build.gradle.kts|gemfile|composer.json|mix.exs|deno.json|*.csproj)
                    F_METADATA=$b ;;
            esac
        fi
    done < <(find "$1" -maxdepth 1 -type f -print0 2>/dev/null)
}

check_env_note() {
    # Prints a warning sentence if .env exists but is not ignored; else nothing.
    [ -f "$1/.env" ] || return 0
    if [ -z "$F_GITIGNORE" ]; then printf '.env exists but there is no .gitignore'; return 0; fi
    if grep -qi '\.env' "$1/$F_GITIGNORE" 2>/dev/null; then return 0; fi
    printf '.env exists but is not covered by .gitignore'
}

scan_targets() {
    # Tracked files in a git repo (what would actually get published);
    # otherwise a plain folder walk for pre-repo folders and empty repos.
    if is_git_repo "$1" && command -v git >/dev/null 2>&1; then
        local rel r
        rel=$(git -C "$1" ls-files 2>/dev/null) || rel=""
        if [ -n "$rel" ]; then
            while IFS= read -r r; do [ -n "$r" ] && printf '%s/%s\n' "$1" "$r"; done <<<"$rel"
            return 0
        fi
    fi
    find "$1" \
        \( -name .git -o -name node_modules -o -name .venv -o -name venv -o -name dist -o -name build -o -name target -o -name vendor -o -name __pycache__ \) -prune \
        -o -type f -print 2>/dev/null | head -n 3000
}

# Quote character classes (kept as variables because quoting them inline in
# the regex below is unreadable). Note: brackets must not be nested, or the
# regex engine mis-parses the character class.
QOPT='["'"'"']'             # ["']              optional opening quote
QVAL='[^[:space:]"'"'"']'   # [^[:space:]"']    value chars: no whitespace, no quotes

SECRET_NAME=( "private key block" "AWS access key" "GitHub token" "Google API key" "Slack token" "OpenAI-style key" "credential assignment" )
SECRET_REGEX=( \
    '-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----' \
    'AKIA[0-9A-Z]{16}' \
    'gh[pousr]_[A-Za-z0-9]{20,}' \
    'AIza[0-9A-Za-z_-]{35}' \
    'xox[baprs]-[A-Za-z0-9-]{10,}' \
    'sk-[A-Za-z0-9_-]{20,}' \
    "(api[_-]?key|api[_-]?secret|secret[_-]?key|secret[_-]?access[_-]?key|access[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)[[:space:]]*[=:][[:space:]]*${QOPT}?${QVAL}{8,}" \
)

PATH_NAME=( "Windows user path" "Unix home path" "absolute Windows path" )
PATH_REGEX=( '[A-Za-z]:\\Users\\' '/(Users|home)/[A-Za-z0-9._-]+' '[A-Za-z]:\\[^[:space:]]' )

# Values like "YOUR_API_KEY_HERE" or "$env:TOKEN" are references, not secrets.
PLACEHOLDER_REGEX='your[_-]?(key|token|secret|password|api)|example|placeholder|change[_-]?me|<[^>]+>|\$\{[^}]*\}|\$env:|process\.env'

find_matches() {  # $1 = dir, $2 = "secrets" | "paths"; prints "name -> path:line"
    local dir=$1
    local -a names regexes
    if [ "$2" = "secrets" ]; then
        names=("${SECRET_NAME[@]}"); regexes=("${SECRET_REGEX[@]}")
    else
        names=("${PATH_NAME[@]}");   regexes=("${PATH_REGEX[@]}")
    fi
    local had_nc=0
    shopt -q nocasematch && had_nc=1
    shopt -s nocasematch
    local f sz ln line i val low
    while IFS= read -r f; do
        [ -f "$f" ] || continue
        case $f in
            *.png|*.jpg|*.jpeg|*.gif|*.ico|*.pdf|*.zip|*.gz|*.tgz|*.7z|*.rar|*.exe|*.dll|*.so|*.dylib|*.bin|*.woff|*.woff2|*.ttf|*.eot|*.otf|*.mp3|*.mp4|*.mov|*.avi|*.jar|*.class|*.pyc|*.pdb|*.node|*.sqlite|*.sqlite3|*.db) continue ;;
        esac
        sz=$(wc -c <"$f" 2>/dev/null) || continue
        [ "$sz" -le 1048576 ] || continue
        ln=0
        while IFS= read -r line || [ -n "$line" ]; do
            ln=$((ln + 1))
            for i in "${!names[@]}"; do
                if [[ $line =~ ${regexes[$i]} ]]; then
                    val=${BASH_REMATCH[0]}
                    low=$(printf '%s' "$val" | tr '[:upper:]' '[:lower:]')
                    if ! printf '%s' "$low" | grep -Eq "$PLACEHOLDER_REGEX"; then
                        printf '%s -> %s:%s\n' "${names[$i]}" "${f#"$dir"/}" "$ln"
                    fi
                    break
                fi
            done
        done <"$f"
    done < <(scan_targets "$dir")
    [ "$had_nc" -eq 1 ] || shopt -u nocasematch
}

convert_to_slug() {
    # https://github.com/OWNER/REPO(.git) | git@github.com:OWNER/REPO(.git) -> OWNER/REPO
    local s
    s=$(printf '%s' "$1" | sed -E -n 's|.*github\.com[/:]([^/]+)/([^/]+).*$|\1/\2|p') || return 0
    [ -n "$s" ] || return 0
    printf '%s\n' "$s" | sed -E 's/\.git$//; s|/$||'
}

# --- GitHub protections (mirrors gh-guard) ------------------------------------

GUARD_BRANCH=explain; GUARD_DEP=explain; GUARD_SECRET=explain

check_guards() {  # $1 = slug (may be empty)
    GUARD_BRANCH=explain; GUARD_DEP=explain; GUARD_SECRET=explain
    [ -n "$1" ] || return 0
    command -v gh >/dev/null 2>&1 || return 0
    local slug=$1 names bf sf st
    if [ "$APPLY" -eq 0 ]; then
        # Dry run: read-only queries, nothing is changed.
        names=$(gh api "repos/$slug/rulesets" --jq '.[].name' 2>/dev/null) || return 0
        if printf '%s\n' "$names" | grep -qx 'protect-default-branch'; then GUARD_BRANCH=ok; else GUARD_BRANCH=pending; fi
        if gh api "repos/$slug/vulnerability-alerts" >/dev/null 2>&1; then GUARD_DEP=ok; else GUARD_DEP=pending; fi
        st=$(gh api "repos/$slug" --jq '.security_and_analysis.secret_scanning_push_protection.status' 2>/dev/null || true)
        if [ "$st" = "enabled" ]; then GUARD_SECRET=ok; else GUARD_SECRET=pending; fi
    else
        names=$(gh api "repos/$slug/rulesets" --jq '.[].name' 2>/dev/null) || names=""
        if printf '%s\n' "$names" | grep -qx 'protect-default-branch'; then
            GUARD_BRANCH=ok
        else
            bf=$(mktemp); printf '%s' "$BRANCH_JSON" >"$bf"
            if gh api -X POST "repos/$slug/rulesets" --input "$bf" >/dev/null 2>&1; then GUARD_BRANCH=ok; else GUARD_BRANCH=plan-limited; fi
            rm -f "$bf"
        fi
        if gh api -X PUT "repos/$slug/vulnerability-alerts" --silent >/dev/null 2>&1; then GUARD_DEP=ok; else GUARD_DEP=unavailable; fi
        sf=$(mktemp); printf '%s' "$SECRET_JSON" >"$sf"
        st=$(gh api -X PATCH "repos/$slug" --input "$sf" 2>/dev/null --jq '.security_and_analysis.secret_scanning_push_protection.status' || true)
        if [ "$st" = "enabled" ]; then GUARD_SECRET=ok; else GUARD_SECRET=manual; fi
        rm -f "$sf"
    fi
}

show_guard() {  # $1 label, $2 state, $3 ok-text
    local label=$1 state=$2 oktext=$3 msg="" color="$C_WARN" sym="!"
    case $state in
        ok)           msg=$oktext ;;
        pending)      msg="would enable (use --apply)" ;;
        plan-limited) msg="plan-limited (private needs GitHub Pro)" ;;
        unavailable)  msg="unavailable" ;;
        manual)       msg="needs one click (Settings > Advanced Security)" ;;
    esac
    if [ "$state" = "ok" ]; then color="$C_OK"; sym="+"; fi
    printf '%s[%s]%s %-19s: %s\n' "$color" "$sym" "$C_OFF" "$label" "$msg"
}

show_guards() {
    if [ "$GUARD_BRANCH" = "explain" ]; then
        warn "gh not usable here (missing, no GitHub remote, or repo unreachable) - enable manually in repo Settings:"
        printf '    Branches > Rules > Rulesets: block force-push and default-branch deletion\n'
        printf '    Advanced Security: Dependabot alerts + secret scanning push protection\n'
        return 0
    fi
    local oktext="already enabled"
    [ "$APPLY" -eq 1 ] && oktext="enabled"
    show_guard "branch rules"      "$GUARD_BRANCH" "$oktext"
    show_guard "dependabot alerts" "$GUARD_DEP"    "$oktext"
    show_guard "secret push block" "$GUARD_SECRET" "$oktext"
}

# --- launch checklist ---------------------------------------------------------

build_checklist() {
    # $1=is_repo(0/1) $2=readme $3=license $4=gitignore $5=metadata
    # $6=secrets_count $7=paths_count $8=env_note, then pending guard items.
    local is_repo=$1 readme=$2 license=$3 gitignore=$4 metadata=$5 secrets_n=$6 paths_n=$7 env_note=$8
    CHECKLIST=()
    [ "$is_repo" = "1" ]   || CHECKLIST+=("Run git init in this folder")
    [ -n "$readme" ]       || CHECKLIST+=("Write a README.md (what it is, how to run it)")
    [ -n "$license" ]      || CHECKLIST+=("Add a LICENSE (https://choosealicense.com)")
    [ -n "$gitignore" ]    || CHECKLIST+=("Create a .gitignore")
    [ -n "$metadata" ]     || CHECKLIST+=("Add project metadata (package.json, pyproject.toml, go.mod, ...)")
    [ "$secrets_n" -eq 0 ] || CHECKLIST+=("Remove or move the $secrets_n likely secret(s) out of tracked files; rotate any key that was ever pushed")
    [ -n "$env_note" ]     && CHECKLIST+=("Ignore .env before the first push")
    [ "$paths_n" -eq 0 ]   || CHECKLIST+=("Replace $paths_n personal/machine-specific path(s) with portable ones")
    shift 8 2>/dev/null || true  # drop the eight fixed args, keep pending items
    local g
    for g in "$@"; do CHECKLIST+=("$g"); done
    [ "${#CHECKLIST[@]}" -gt 0 ] || CHECKLIST+=("All clear - give the repo a final read-through, then publish when ready")
}

# --- main ---------------------------------------------------------------------

main() {
    command -v git >/dev/null 2>&1 || { err "git not found - https://git-scm.com"; exit 1; }
    while [ $# -gt 0 ]; do
        case "$1" in
            --path)    [ -n "${2:-}" ] || usage; TARGET="$2"; shift 2 ;;
            --apply)   APPLY=1; shift ;;
            --dry-run) shift ;;  # dry-run is already the default; accepted for explicitness
            -h|--help) usage ;;
            *)         echo "unknown arg: $1" >&2; usage ;;
        esac
    done
    local root
    root=$(cd "$TARGET" 2>/dev/null && pwd) || { err "folder not found: $TARGET"; exit 1; }

    printf 'GitHub Project Launch Kit\n'
    printf 'folder : %s\n' "$root"
    if [ "$APPLY" -eq 1 ]; then printf 'mode   : apply\n'
    else printf 'mode   : dry run (nothing will be changed)\n'; fi

    # 1. Repository
    section "Repository"
    local is_repo=0
    if is_git_repo "$root"; then is_repo=1; ok "Git repository detected"
    else err "not a Git repository (.git not found)"; fi

    # 2. Project files
    section "Project files"
    find_project_files "$root"
    if [ -n "$F_README" ];    then ok "README: $F_README";          else warn "README not found"; fi
    if [ -n "$F_LICENSE" ];   then ok "LICENSE: $F_LICENSE";        else warn "LICENSE not found"; fi
    if [ -n "$F_GITIGNORE" ]; then ok ".gitignore present";         else warn ".gitignore not found"; fi
    if [ -n "$F_METADATA" ];  then ok "project metadata: $F_METADATA"; else warn "no project metadata (package.json, pyproject.toml, go.mod, ...)"; fi

    # 3. Secrets & personal paths
    section "Secrets & personal paths"
    local -a secret_hits=() path_hits=()
    local h
    while IFS= read -r h; do [ -n "$h" ] && secret_hits+=("$h"); done < <(find_matches "$root" "secrets")
    while IFS= read -r h; do [ -n "$h" ] && path_hits+=("$h");   done < <(find_matches "$root" "paths")
    local env_note; env_note=$(check_env_note "$root")

    if [ "${#secret_hits[@]}" -gt 0 ]; then
        for h in "${secret_hits[@]}"; do err "possible secret: $h"; done
    else
        ok "no obvious secrets in tracked files"
    fi
    [ -n "$env_note" ] && warn "$env_note"
    if [ "${#path_hits[@]}" -gt 0 ]; then
        for h in "${path_hits[@]}"; do warn "personal path: $h"; done
    else
        ok "no personal paths found"
    fi

    # 4. GitHub protections
    section "GitHub protections"
    local slug=""
    if [ "$is_repo" -eq 1 ]; then
        local url; url=$(git -C "$root" remote get-url origin 2>/dev/null || true)
        slug=$(convert_to_slug "$url")
    fi
    check_guards "$slug"
    show_guards

    # 5. Launch checklist
    section "Launch checklist"
    local -a pending=()
    [ "$GUARD_BRANCH" = "pending" ]      && pending+=("Enable branch rules (block force-push + default-branch deletion)")
    [ "$GUARD_BRANCH" = "plan-limited" ] && pending+=("Branch rules: private repo needs GitHub Pro, or add branch protection manually")
    [ "$GUARD_BRANCH" = "explain" ]      && pending+=("Enable branch protection + Dependabot + secret push protection in repo Settings (install the gh CLI to automate)")
    { [ "$GUARD_DEP" = "pending" ] || [ "$GUARD_DEP" = "unavailable" ]; } && pending+=("Turn on Dependabot alerts (Settings > Advanced Security)")
    { [ "$GUARD_SECRET" = "pending" ] || [ "$GUARD_SECRET" = "manual" ]; } && pending+=("Turn on secret scanning push protection (Settings > Advanced Security)")
    build_checklist "$is_repo" "$F_README" "$F_LICENSE" "$F_GITIGNORE" "$F_METADATA" \
        "${#secret_hits[@]}" "${#path_hits[@]}" "$env_note" ${pending[@]+"${pending[@]}"}
    local item
    for item in "${CHECKLIST[@]}"; do printf '  - [ ] %s\n' "$item"; done
    if [ "$APPLY" -eq 1 ]; then
        if [ -e "$root/LAUNCH-CHECKLIST.md" ]; then
            warn "LAUNCH-CHECKLIST.md already exists - left untouched"
        else
            {
                printf '# Launch checklist\n\nGenerated by GitHub Project Launch Kit on %s.\n\n' "$(date +%F)"
                for item in "${CHECKLIST[@]}"; do printf -- '- [ ] %s\n' "$item"; done
            } >"$root/LAUNCH-CHECKLIST.md"
            ok "wrote LAUNCH-CHECKLIST.md"
        fi
    fi

    printf '\n'
    if [ "$APPLY" -eq 1 ]; then ok "Done. Nothing was deleted, force-pushed or published."
    else warn "dry run - nothing changed. Re-run with --apply to enable guards and write LAUNCH-CHECKLIST.md."; fi

    if [ "$is_repo" -eq 0 ] || [ "${#secret_hits[@]}" -gt 0 ]; then exit 1; fi
    exit 0
}

# --- entry point --------------------------------------------------------------
# Run only when invoked directly; skipped when sourced by the tests.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then main "$@"; fi
