#Requires -Version 5.1
<#
.SYNOPSIS
  launch-kit - prepare a folder for its GitHub launch. No AI, no magic.

.DESCRIPTION
  Read-only checks by default (dry run):
    1. Is this folder a Git repository?
    2. README / LICENSE / .gitignore / project metadata present?
    3. Likely secrets and personal absolute paths in tracked files?
    4. GitHub protections (branch rules, Dependabot, secret push protection):
       enabled via the gh CLI with -Apply, or explained for manual setup.
    5. Prints a launch checklist; -Apply also writes LAUNCH-CHECKLIST.md.

  Dry-run by default. With -Apply the tool only enables the same three guards
  as gh-guard (identical ruleset name, so both tools skip each other's rules)
  and writes LAUNCH-CHECKLIST.md. It never deletes files, never force-pushes,
  never changes remotes and never publishes anything.

.EXAMPLE
  .\launch-kit.ps1                    # dry-run checks on the current folder
  .\launch-kit.ps1 -Path C:\code\api  # check another folder
  .\launch-kit.ps1 -Apply             # apply GitHub guards + write checklist

.NOTES
  Requires git. gh CLI is optional and only used for GitHub protections.
  Exit code 1 when the folder is not a git repo or likely secrets were found.
#>
param(
    [string]$Path = ".",
    [switch]$Apply,
    [switch]$DryRun  # dry-run is already the default; accepted for explicitness
)

$ErrorActionPreference = "Stop"

# --- constants ----------------------------------------------------------------

# Guard payloads: byte-identical to gh-guard's, so the two tools stay in sync.
$script:BranchJson = '{"name":"protect-default-branch","target":"branch","enforcement":"active","conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]}},"bypass_actors":[],"rules":[{"type":"deletion"},{"type":"non_fast_forward"}]}'
$script:SecretJson = '{"security_and_analysis":{"secret_scanning_push_protection":{"status":"enabled"}}}'

$script:Utf8 = [Text.UTF8Encoding]::new($false)

$script:MetadataFiles = @(
    'package.json','pyproject.toml','setup.py','setup.cfg','requirements.txt',
    'Cargo.toml','go.mod','pom.xml','build.gradle','build.gradle.kts',
    'Gemfile','composer.json','mix.exs','deno.json','*.csproj'
)

$script:SecretPatterns = @(
    @{ Name = 'private key block';     Regex = '-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----' },
    @{ Name = 'AWS access key';        Regex = 'AKIA[0-9A-Z]{16}' },
    @{ Name = 'GitHub token';          Regex = 'gh[pousr]_[A-Za-z0-9]{20,}' },
    @{ Name = 'Google API key';        Regex = 'AIza[0-9A-Za-z_\-]{35}' },
    @{ Name = 'Slack token';           Regex = 'xox[baprs]-[A-Za-z0-9\-]{10,}' },
    @{ Name = 'OpenAI-style key';      Regex = 'sk\-[A-Za-z0-9_\-]{20,}' },
    @{ Name = 'credential assignment'; Regex = '(?i)(api[_-]?key|api[_-]?secret|secret[_-]?key|secret[_-]?access[_-]?key|access[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b\s*[=:]\s*["'']?[^\s"'']{8,}' }
)

$script:PersonalPathPatterns = @(
    @{ Name = 'Windows user path';     Regex = '[A-Za-z]:\\Users\\' },
    @{ Name = 'Unix home path';        Regex = '/(Users|home)/[A-Za-z0-9._\-]+/' },
    @{ Name = 'absolute Windows path'; Regex = '[A-Za-z]:\\[^\s]' }
)

# Values like "YOUR_API_KEY_HERE" or "$env:TOKEN" are references, not secrets.
$script:PlaceholderRegex = '(?i)your[_-]?(key|token|secret|password|api)|example|placeholder|change[_-]?me|<[^>]+>|\$\{[^}]*\}|\$env:|process\.env'

$script:BinaryExtRegex = '\.(png|jpe?g|gif|ico|pdf|zip|gz|tgz|7z|rar|exe|dll|so|dylib|bin|woff2?|ttf|eot|otf|mp3|mp4|mov|avi|jar|class|pyc|pdb|node|sqlite3?|db)$'

$script:fRuleset = $null
$script:fSecret  = $null

# --- output -------------------------------------------------------------------

$script:UseColor = $false
try {
    $script:UseColor = [bool]($Host.UI.SupportsForegroundColor) -and
                       -not [Console]::IsOutputRedirected -and
                       -not $env:NO_COLOR
} catch { }

function Out-Finding([string]$Symbol, [string]$Color, [string]$Text) {
    if ($script:UseColor) {
        Write-Host "[$Symbol] " -ForegroundColor $Color -NoNewline
        Write-Host $Text
    }
    else { Write-Host "[$Symbol] $Text" }
}
function Ok([string]$Text)   { Out-Finding '+' 'Green'  $Text }
function Warn([string]$Text) { Out-Finding '!' 'Yellow' $Text }
function Err([string]$Text)  { Out-Finding 'x' 'Red'    $Text }
function Section([string]$Name) {
    Write-Host ""
    if ($script:UseColor) { Write-Host "== $Name ==" -ForegroundColor Cyan }
    else { Write-Host "== $Name ==" }
}

# --- checks -------------------------------------------------------------------

function Test-CommandAvailable([string]$Name) {
    try { $null = Get-Command $Name -ErrorAction Stop; return $true } catch { return $false }
}

function Invoke-Native([string]$File, [string[]]$ToolArgs) {
    # Native tools report failure on stderr; with $ErrorActionPreference=Stop
    # PowerShell turns redirected stderr into terminating errors. Relax it here
    # and decide by exit code instead.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $out = & $File @ToolArgs 2>$null
        return @{ Ok = ($LASTEXITCODE -eq 0); Output = (@($out) -join "`n") }
    }
    finally { $ErrorActionPreference = $prev }
}

function Test-GitRepo([string]$Dir) {
    # .git may be a directory or a file (worktrees/submodules)
    return (Test-Path -LiteralPath (Join-Path $Dir ".git"))
}

function Get-ProjectFiles([string]$Dir) {
    $files = @(Get-ChildItem -LiteralPath $Dir -File -ErrorAction SilentlyContinue)
    $readme  = $files | Where-Object { $_.Name -match '^readme' } | Select-Object -First 1
    $license = $files | Where-Object { $_.Name -match '^(license|licence|copying)' } | Select-Object -First 1
    $ign     = $files | Where-Object { $_.Name -eq '.gitignore' } | Select-Object -First 1
    $meta    = $null
    foreach ($m in $script:MetadataFiles) {
        $meta = $files | Where-Object { $_.Name -like $m } | Select-Object -First 1
        if ($meta) { break }
    }
    return @{
        Readme    = $(if ($readme)  { $readme.Name  } else { "" })
        License   = $(if ($license) { $license.Name } else { "" })
        Gitignore = $(if ($ign)     { $ign.Name     } else { "" })
        Metadata  = $(if ($meta)    { $meta.Name    } else { "" })
    }
}

function Get-EnvNote([string]$Dir, [hashtable]$Files) {
    if (-not (Test-Path -LiteralPath (Join-Path $Dir ".env") -PathType Leaf)) { return "" }
    if (-not $Files.Gitignore) { return ".env exists but there is no .gitignore" }
    $lines = @(Get-Content -LiteralPath (Join-Path $Dir $Files.Gitignore) -ErrorAction SilentlyContinue)
    if (@($lines) -match '\.env') { return "" }
    return ".env exists but is not covered by .gitignore"
}

function Get-ScanTargets([string]$Dir) {
    # Tracked files in a git repo (what would actually get published);
    # otherwise a plain folder walk for pre-repo folders and empty repos.
    if ((Test-GitRepo $Dir) -and (Test-CommandAvailable "git")) {
        $r = Invoke-Native "git" @("-C", $Dir, "ls-files")
        $paths = @($r.Output -split "`r?`n" | Where-Object { $_ } | ForEach-Object { Join-Path $Dir $_ })
        if ($paths.Count -gt 0) { return $paths }
    }
    $skip = '\\(\.git|node_modules|\.venv|venv|dist|build|target|vendor|__pycache__)(\\|$)'
    return @(Get-ChildItem -LiteralPath $Dir -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch $skip } |
        Select-Object -First 3000 -ExpandProperty FullName)
}

function Get-RelPath([string]$Base, [string]$Full) {
    try {
        $b = [IO.Path]::GetFullPath($Base)
        $f = [IO.Path]::GetFullPath($Full)
        if ($f.StartsWith($b, [StringComparison]::OrdinalIgnoreCase)) {
            return $f.Substring($b.Length).TrimStart('\', '/')
        }
    } catch { }
    return $Full
}

function Find-Matches([string]$Dir, [string]$Kind) {
    $patterns = $(if ($Kind -eq "secrets") { $script:SecretPatterns } else { $script:PersonalPathPatterns })
    $hits = @()
    $count = 0
    foreach ($file in (Get-ScanTargets $Dir)) {
        $count++
        if ($count -gt 3000) { break }
        if ($file -match $script:BinaryExtRegex) { continue }
        $item = Get-Item -LiteralPath $file -ErrorAction SilentlyContinue
        if (-not $item -or $item.Length -gt 1MB) { continue }
        $lines = $null
        try { $lines = @(Get-Content -LiteralPath $file -ErrorAction Stop) } catch { continue }
        for ($i = 0; $i -lt $lines.Count; $i++) {
            foreach ($p in $patterns) {
                if ($lines[$i] -match $p.Regex) {
                    if ("$($Matches[0])" -notmatch $script:PlaceholderRegex) {
                        $hits += ("{0} -> {1}:{2}" -f $p.Name, (Get-RelPath $Dir $file), ($i + 1))
                    }
                    break
                }
            }
        }
    }
    return $hits
}

function Find-Secrets([string]$Dir)        { Find-Matches $Dir "secrets" }
function Find-PersonalPaths([string]$Dir)  { Find-Matches $Dir "paths" }

function ConvertTo-GithubSlug([string]$Url) {
    # https://github.com/OWNER/REPO(.git) | git@github.com:OWNER/REPO(.git) -> OWNER/REPO
    $Url = "$Url".Trim()
    if ($Url -match 'github\.com[/:]([^/]+)/([^/]+?)(?:\.git)?/?$') {
        return "$($Matches[1])/$($Matches[2])"
    }
    return ""
}

# --- GitHub protections (mirrors gh-guard) ------------------------------------

function Invoke-GuardChecks([string]$Slug, [bool]$Apply) {
    # States: ok | pending | plan-limited | unavailable | manual | explain
    $g = [ordered]@{ Branch = "explain"; Dependabot = "explain"; SecretPush = "explain" }
    if (-not $Slug) { return $g }
    if (-not (Test-CommandAvailable "gh")) { return $g }
    $r = Invoke-Native "gh" @("api", "repos/$Slug/rulesets", "--jq", ".[].name")
    if (-not $r.Ok) { return $g }
    $names = @($r.Output -split "`r?`n" | Where-Object { $_ })
    if (-not $Apply) {
        # Dry run: read-only queries, nothing is changed.
        $g["Branch"] = if ($names -contains "protect-default-branch") { "ok" } else { "pending" }
        $r = Invoke-Native "gh" @("api", "repos/$Slug/vulnerability-alerts")
        $g["Dependabot"] = if ($r.Ok) { "ok" } else { "pending" }
        $r = Invoke-Native "gh" @("api", "repos/$Slug", "--jq", ".security_and_analysis.secret_scanning_push_protection.status")
        $g["SecretPush"] = if ($r.Ok -and $r.Output.Trim() -eq "enabled") { "ok" } else { "pending" }
        return $g
    }
    # Apply mode: same three calls as gh-guard, idempotent, nothing deleted.
    if ($names -contains "protect-default-branch") { $g["Branch"] = "ok" }
    else {
        $r = Invoke-Native "gh" @("api", "-X", "POST", "repos/$Slug/rulesets", "--input", $script:fRuleset)
        $g["Branch"] = if ($r.Ok) { "ok" } else { "plan-limited" }
    }
    $r = Invoke-Native "gh" @("api", "-X", "PUT", "repos/$Slug/vulnerability-alerts", "--silent")
    $g["Dependabot"] = if ($r.Ok) { "ok" } else { "unavailable" }
    $r = Invoke-Native "gh" @("api", "-X", "PATCH", "repos/$Slug", "--input", $script:fSecret)
    $state = ""
    if ($r.Ok) {
        try { $state = ($r.Output | ConvertFrom-Json).security_and_analysis.secret_scanning_push_protection.status } catch { }
    }
    $g["SecretPush"] = if ($state -eq "enabled") { "ok" } else { "manual" }
    return $g
}

function Show-Guard([string]$Label, [string]$State, [string]$OkText) {
    switch ($State) {
        "ok"           { Ok   (("{0,-19}: " -f $Label) + $OkText) }
        "pending"      { Warn (("{0,-19}: " -f $Label) + "would enable (use -Apply)") }
        "plan-limited" { Warn (("{0,-19}: " -f $Label) + "plan-limited (private needs GitHub Pro)") }
        "unavailable"  { Warn (("{0,-19}: " -f $Label) + "unavailable") }
        "manual"       { Warn (("{0,-19}: " -f $Label) + "needs one click (Settings > Advanced Security)") }
    }
}

function Show-Guards([object]$Guards, [bool]$Apply) {
    if ($Guards["Branch"] -eq "explain") {
        Warn "gh not usable here (missing, no GitHub remote, or repo unreachable) - enable manually in repo Settings:"
        Write-Host "    Branches > Rules > Rulesets: block force-push and default-branch deletion"
        Write-Host "    Advanced Security: Dependabot alerts + secret scanning push protection"
        return
    }
    $okText = "already enabled"
    if ($Apply) { $okText = "enabled" }
    Show-Guard "branch rules"      $Guards["Branch"]     $okText
    Show-Guard "dependabot alerts" $Guards["Dependabot"] $okText
    Show-Guard "secret push block" $Guards["SecretPush"] $okText
}

function Get-PendingGuardItems([object]$Guards) {
    $items = @()
    if ($Guards["Branch"] -eq "pending")      { $items += "Enable branch rules (block force-push + default-branch deletion)" }
    if ($Guards["Branch"] -eq "plan-limited") { $items += "Branch rules: private repo needs GitHub Pro, or add branch protection manually" }
    if ($Guards["Branch"] -eq "explain")      { $items += "Enable branch protection + Dependabot + secret push protection in repo Settings (install the gh CLI to automate)" }
    if ($Guards["Dependabot"] -in "pending", "unavailable") { $items += "Turn on Dependabot alerts (Settings > Advanced Security)" }
    if ($Guards["SecretPush"] -in "pending", "manual")      { $items += "Turn on secret scanning push protection (Settings > Advanced Security)" }
    return $items
}

# --- launch checklist ---------------------------------------------------------

function New-Checklist([bool]$IsRepo, [hashtable]$Files, [array]$Secrets, [array]$Paths,
                       [string]$EnvNote, [array]$PendingGuards) {
    $items = @()
    if (-not $IsRepo)         { $items += "Run git init in this folder" }
    if (-not $Files.Readme)   { $items += "Write a README.md (what it is, how to run it)" }
    if (-not $Files.License)  { $items += "Add a LICENSE (https://choosealicense.com)" }
    if (-not $Files.Gitignore){ $items += "Create a .gitignore" }
    if (-not $Files.Metadata) { $items += "Add project metadata (package.json, pyproject.toml, go.mod, ...)" }
    if (@($Secrets).Count -gt 0) { $items += "Remove or move the $($Secrets.Count) likely secret(s) out of tracked files; rotate any key that was ever pushed" }
    if ($EnvNote)             { $items += "Ignore .env before the first push" }
    if (@($Paths).Count -gt 0) { $items += "Replace $($Paths.Count) personal/machine-specific path(s) with portable ones" }
    foreach ($g in $PendingGuards) { $items += $g }
    if ($items.Count -eq 0)   { $items += "All clear - give the repo a final read-through, then publish when ready" }
    return $items
}

function Show-Checklist([string[]]$Items) {
    foreach ($i in $Items) { Write-Host "  - [ ] $i" }
}

function Write-ChecklistFile([string]$Root, [string[]]$Items) {
    $p = Join-Path $Root "LAUNCH-CHECKLIST.md"
    if (Test-Path -LiteralPath $p) { Warn "LAUNCH-CHECKLIST.md already exists - left untouched"; return }
    $sb = "# Launch checklist`r`n`r`nGenerated by GitHub Project Launch Kit on $(Get-Date -Format 'yyyy-MM-dd').`r`n`r`n"
    foreach ($i in $Items) { $sb += "- [ ] $i`r`n" }
    [IO.File]::WriteAllText($p, $sb, $script:Utf8)
    Ok "wrote LAUNCH-CHECKLIST.md"
}

# --- main ---------------------------------------------------------------------

function Main {
    if (-not (Test-CommandAvailable "git")) { Err "git not found - install https://git-scm.com"; exit 1 }
    if (-not (Test-Path -LiteralPath $Path)) { Err "folder not found: $Path"; exit 1 }
    $root = (Resolve-Path -LiteralPath $Path).Path

    Write-Host "GitHub Project Launch Kit"
    Write-Host "folder : $root"
    if ($Apply) { Write-Host "mode   : apply" }
    else        { Write-Host "mode   : dry run (nothing will be changed)" }

    if ($Apply) {
        $script:fRuleset = Join-Path ([IO.Path]::GetTempPath()) "launch-kit-ruleset.json"
        $script:fSecret  = Join-Path ([IO.Path]::GetTempPath()) "launch-kit-secret.json"
        [IO.File]::WriteAllText($script:fRuleset, $script:BranchJson, $script:Utf8)
        [IO.File]::WriteAllText($script:fSecret,  $script:SecretJson,  $script:Utf8)
    }

    try {
        # 1. Repository
        Section "Repository"
        $isRepo = Test-GitRepo $root
        if ($isRepo) { Ok "Git repository detected" }
        else         { Err "not a Git repository (.git not found)" }

        # 2. Project files
        Section "Project files"
        $files = Get-ProjectFiles $root
        if ($files.Readme)    { Ok "README: $($files.Readme)" }        else { Warn "README not found" }
        if ($files.License)   { Ok "LICENSE: $($files.License)" }      else { Warn "LICENSE not found" }
        if ($files.Gitignore) { Ok ".gitignore present" }              else { Warn ".gitignore not found" }
        if ($files.Metadata)  { Ok "project metadata: $($files.Metadata)" } else { Warn "no project metadata (package.json, pyproject.toml, go.mod, ...)" }

        # 3. Secrets & personal paths
        Section "Secrets & personal paths"
        $secrets = @(Find-Secrets $root)
        $paths   = @(Find-PersonalPaths $root)
        $envNote = Get-EnvNote $root $files
        if ($secrets.Count -gt 0) { foreach ($s in $secrets) { Err "possible secret: $s" } }
        else { Ok "no obvious secrets in tracked files" }
        if ($envNote) { Warn $envNote }
        if ($paths.Count -gt 0) { foreach ($p in $paths) { Warn "personal path: $p" } }
        else { Ok "no personal paths found" }

        # 4. GitHub protections
        Section "GitHub protections"
        $slug = ""
        if ($isRepo) {
            $r = Invoke-Native "git" @("-C", $root, "remote", "get-url", "origin")
            $slug = ConvertTo-GithubSlug $r.Output
        }
        $guards = Invoke-GuardChecks $slug $Apply
        Show-Guards $guards $Apply

        # 5. Launch checklist
        Section "Launch checklist"
        $pending = @(Get-PendingGuardItems $guards)
        $items = @(New-Checklist $isRepo $files $secrets $paths $envNote $pending)
        Show-Checklist $items
        if ($Apply) { Write-ChecklistFile $root $items }
    }
    finally {
        if ($Apply) { Remove-Item $script:fRuleset, $script:fSecret -ErrorAction SilentlyContinue }
    }

    Write-Host ""
    if ($Apply) { Ok "Done. Nothing was deleted, force-pushed or published." }
    else        { Warn "dry run - nothing changed. Re-run with -Apply to enable guards and write LAUNCH-CHECKLIST.md." }

    if ((-not $isRepo) -or ($secrets.Count -gt 0)) { exit 1 }
    exit 0
}

# --- entry point --------------------------------------------------------------
# Run only when invoked directly; skipped when dot-sourced by the tests.
if ($MyInvocation.InvocationName -ne '.') { Main }
