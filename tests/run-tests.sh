#!/usr/bin/env bash
# Focused tests for the launch-kit checks. No test framework, no dependencies.
# Run: bash tests/run-tests.sh

set -u

# Source the script: defines the check functions, skips the main run.
. "$(dirname "$0")/../launch-kit.sh"

p=0; f=0
okmsg()   { p=$((p+1)); printf 'ok   - %s\n' "$1"; }
failmsg() { f=$((f+1)); printf 'FAIL - %s\n' "$1"; }
assert_eq()       { if [ "$2" = "$3" ]; then okmsg "$1"; else failmsg "$1 (got: $2)"; fi; }
assert_match()    { if printf '%s' "$2" | grep -q "$3"; then okmsg "$1"; else failmsg "$1"; fi; }
assert_no_match() { if printf '%s' "$2" | grep -q "$3"; then failmsg "$1"; else okmsg "$1"; fi; }
assert_true()     { local n=$1; shift; if "$@" >/dev/null 2>&1; then okmsg "$n"; else failmsg "$n"; fi; }
assert_false()    { local n=$1; shift; if "$@" >/dev/null 2>&1; then failmsg "$n"; else okmsg "$n"; fi; }

tmp=$(mktemp -d "${TMPDIR:-/tmp}/launch-kit-tests.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/plain" "$tmp/repo/.git" "$tmp/empty" "$tmp/full" "$tmp/sec" "$tmp/pp" "$tmp/envd"

# --- 1. git repository detection ------------------------------------------------
assert_false "plain folder is not a git repo" is_git_repo "$tmp/plain"
assert_true  "folder with .git is a git repo" is_git_repo "$tmp/repo"

# --- 2. project file detection --------------------------------------------------
find_project_files "$tmp/empty"
assert_eq "empty folder: README missing"     "" "$F_README"
assert_eq "empty folder: LICENSE missing"    "" "$F_LICENSE"
assert_eq "empty folder: .gitignore missing" "" "$F_GITIGNORE"
assert_eq "empty folder: no metadata"        "" "$F_METADATA"

printf 'hi\n'            >"$tmp/full/README.md"
printf 'MIT\n'           >"$tmp/full/LICENSE"
printf 'node_modules\n'  >"$tmp/full/.gitignore"
printf '{}\n'            >"$tmp/full/package.json"
find_project_files "$tmp/full"
assert_eq "README found"                      "README.md"    "$F_README"
assert_eq "LICENSE found"                     "LICENSE"      "$F_LICENSE"
assert_eq ".gitignore found"                  ".gitignore"   "$F_GITIGNORE"
assert_eq "package.json detected as metadata" "package.json" "$F_METADATA"

# --- 3. .env exposure note ------------------------------------------------------
printf 'SECRET=1\n' >"$tmp/envd/.env"
find_project_files "$tmp/envd"
assert_match ".env without .gitignore flagged" "$(check_env_note "$tmp/envd")" "no .gitignore"
printf '.env\n' >"$tmp/envd/.gitignore"
find_project_files "$tmp/envd"
assert_eq ".env covered by .gitignore passes" "" "$(check_env_note "$tmp/envd")"

# --- 4. secret detection --------------------------------------------------------
# Fake credentials, assembled at run time so this file never contains a
# pattern-matching literal (keeps secret scanners quiet about the tests).
aws_key="AKIA""ABCDEFGHIJKLMNOP"
aws_secret="wJalrXUtnFEMI/""K7MDENG/bPxRfiCY"
private_key="-----BEGIN ""RSA PRIVATE KEY-----"
gh_token="ghp_""abcdefghijklmnopqrstuvwxyz123456"
printf 'aws key %s here\n'                       "$aws_key"    >"$tmp/sec/config.txt"
cred_line="aws_secret_access_""key = $aws_secret"
printf '%s\n'                                    "$cred_line"  >"$tmp/sec/aws-secret.txt"
printf -- '%s\nabc\n'                            "$private_key" >"$tmp/sec/id_rsa"
printf 'my token is %s\n'                        "$gh_token"   >"$tmp/sec/notes.md"
printf 'just regular text, nothing to see\n'     >"$tmp/sec/clean.txt"
printf 'API_KEY = "YOUR_EXAMPLE_KEY_HERE"\n'     >"$tmp/sec/placeholder.txt"
hits=$(find_matches "$tmp/sec" "secrets")
assert_match    "AWS access key detected"        "$hits" "AWS access key"
assert_match    "credential assignment detected" "$hits" "credential assignment -> aws-secret.txt"
assert_match    "private key detected"           "$hits" "private key block"
assert_match    "GitHub token detected"          "$hits" "GitHub token"
assert_no_match "clean file not flagged"         "$hits" "clean.txt"
assert_no_match "placeholder value not flagged"  "$hits" "placeholder.txt"

# --- 5. personal path detection -------------------------------------------------
win_user="C:""\Users\ean\Documents\report.docx"
unix_home="/ho""me/alice/build.log"
printf 'see %s\n'             "$win_user"  >"$tmp/pp/a.txt"
printf 'logs at %s\n'         "$unix_home" >"$tmp/pp/b.txt"
printf 'portable relative path ./data\n'   >"$tmp/pp/c.txt"
phits=$(find_matches "$tmp/pp" "paths")
assert_match    "Windows user path detected" "$phits" "Windows user path -> a.txt"
assert_match    "Unix home path detected"    "$phits" "Unix home path -> b.txt"
assert_no_match "relative path not flagged"  "$phits" "c.txt"

# --- 6. GitHub slug parsing -----------------------------------------------------
assert_eq "https URL parsed"   "ean/api" "$(convert_to_slug "https://github.com/ean/api.git")"
assert_eq "ssh URL parsed"     "ean/api" "$(convert_to_slug "git@github.com:ean/api.git")"
assert_eq "trailing slash ok"  "ean/api" "$(convert_to_slug "https://github.com/ean/api/")"
assert_eq "non-github ignored" ""        "$(convert_to_slug "https://gitlab.com/ean/api.git")"
assert_eq "empty URL ignored"  ""        "$(convert_to_slug "")"

# --- 7. launch checklist --------------------------------------------------------
build_checklist 0 "" "" "" "" 1 0 ""
assert_eq    "checklist: bare folder gets 6 items" "6" "${#CHECKLIST[@]}"
assert_match "checklist: git init suggested"  "$(printf '%s\n' "${CHECKLIST[@]}")" "git init"
assert_match "checklist: license suggested"   "$(printf '%s\n' "${CHECKLIST[@]}")" "LICENSE"
assert_match "checklist: secret item present" "$(printf '%s\n' "${CHECKLIST[@]}")" "secret"
build_checklist 1 README.md LICENSE .gitignore package.json 0 0 ""
assert_eq    "checklist: complete repo gets a single all-clear line" "1" "${#CHECKLIST[@]}"

# --- 8. integration: the real script, dry run -----------------------------------
if command -v git >/dev/null 2>&1; then
    bash "$(dirname "$0")/../launch-kit.sh" --path "$tmp/full" >/dev/null 2>&1
    assert_eq "dry-run on non-repo folder exits 1" "1" "$?"
    bash "$(dirname "$0")/../launch-kit.sh" --path "$tmp/repo" >/dev/null 2>&1
    assert_eq "dry-run on repo fixture exits 0" "0" "$?"
    assert_eq "dry-run wrote no checklist file" "" "$(ls "$tmp/repo/LAUNCH-CHECKLIST.md" 2>/dev/null)"
fi

printf '\n'
if [ "$f" -gt 0 ]; then printf '%s test(s) failed\n' "$f"; exit 1; fi
printf 'all %s tests passed\n' "$p"
