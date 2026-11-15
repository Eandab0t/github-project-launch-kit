# Focused tests for the launch-kit checks. No test framework, no dependencies.
# Run: powershell -NoProfile -ExecutionPolicy Bypass -File tests\run-tests.ps1

$ErrorActionPreference = "Stop"

# Dot-source the script: defines the check functions, skips the main run.
. (Join-Path $PSScriptRoot "..\launch-kit.ps1")

$script:pass = 0
$script:fail = 0

function Assert([string]$Name, [bool]$Condition) {
    if ($Condition) { $script:pass++; Write-Host "ok   - $Name" }
    else            { $script:fail++; Write-Host "FAIL - $Name" }
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("launch-kit-tests-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmp | Out-Null

try {
    # --- 1. git repository detection -------------------------------------------
    $plain = Join-Path $tmp "plain"; New-Item -ItemType Directory $plain | Out-Null
    Assert "plain folder is not a git repo" (-not (Test-GitRepo $plain))
    $repo = Join-Path $tmp "repo"; New-Item -ItemType Directory (Join-Path $repo ".git") -Force | Out-Null
    Assert "folder with .git is a git repo" (Test-GitRepo $repo)

    # --- 2. project file detection ---------------------------------------------
    $empty = Join-Path $tmp "empty"; New-Item -ItemType Directory $empty | Out-Null
    $f = Get-ProjectFiles $empty
    Assert "empty folder: README missing"     (-not $f.Readme)
    Assert "empty folder: LICENSE missing"    (-not $f.License)
    Assert "empty folder: .gitignore missing" (-not $f.Gitignore)
    Assert "empty folder: no metadata"        (-not $f.Metadata)

    $full = Join-Path $tmp "full"; New-Item -ItemType Directory $full | Out-Null
    Set-Content (Join-Path $full "README.md")   "hi"
    Set-Content (Join-Path $full "LICENSE")     "MIT"
    Set-Content (Join-Path $full ".gitignore")  "node_modules"
    Set-Content (Join-Path $full "package.json") "{}"
    $f = Get-ProjectFiles $full
    Assert "README found"                        ($f.Readme -eq "README.md")
    Assert "LICENSE found"                       ($f.License -eq "LICENSE")
    Assert ".gitignore found"                    ($f.Gitignore -eq ".gitignore")
    Assert "package.json detected as metadata"   ($f.Metadata -eq "package.json")

    # --- 3. .env exposure note --------------------------------------------------
    $envDir = Join-Path $tmp "envd"; New-Item -ItemType Directory $envDir | Out-Null
    Set-Content (Join-Path $envDir ".env") "SECRET=1"
    Assert ".env without .gitignore flagged"   ((Get-EnvNote $envDir @{ Gitignore = "" }) -ne "")
    Set-Content (Join-Path $envDir ".gitignore") ".env`n"
    Assert ".env covered by .gitignore passes" ((Get-EnvNote $envDir @{ Gitignore = ".gitignore" }) -eq "")

    # --- 4. secret detection ----------------------------------------------------
    # Fake credentials, assembled at run time so this file never contains a
    # pattern-matching literal (keeps secret scanners quiet about the tests).
    $sec = Join-Path $tmp "sec"; New-Item -ItemType Directory $sec | Out-Null
    $awsKey     = 'AKIA' + 'ABCDEFGHIJKLMNOP'
    $awsSecret  = 'wJalrXUtnFEMI/' + 'K7MDENG/bPxRfiCY'
    $privateKey = '-----BEGIN ' + 'RSA PRIVATE KEY-----'
    $ghToken    = 'ghp_' + 'abcdefghijklmnopqrstuvwxyz123456'
    Set-Content (Join-Path $sec "config.txt")     "aws key $awsKey here"
    $credLine = 'aws_secret_access_' + "key = $awsSecret"
    Set-Content (Join-Path $sec "aws-secret.txt") $credLine
    Set-Content (Join-Path $sec "id_rsa")         "${privateKey}`nabc"
    Set-Content (Join-Path $sec "notes.md")       "my token is $ghToken"
    Set-Content (Join-Path $sec "clean.txt")      "just regular text, nothing to see"
    Set-Content (Join-Path $sec "placeholder.txt") 'API_KEY = "YOUR_EXAMPLE_KEY_HERE"'
    $hits = @(Find-Secrets $sec)
    Assert "AWS access key detected"       (@($hits | Where-Object { $_ -match "AWS access key" }).Count -gt 0)
    Assert "credential assignment detected" (@($hits | Where-Object { $_ -match "credential assignment" -and $_ -match "aws-secret.txt" }).Count -gt 0)
    Assert "private key detected"          (@($hits | Where-Object { $_ -match "private key block" }).Count -gt 0)
    Assert "GitHub token detected"         (@($hits | Where-Object { $_ -match "GitHub token" }).Count -gt 0)
    Assert "clean file not flagged"        (@($hits | Where-Object { $_ -match "clean\.txt" }).Count -eq 0)
    Assert "placeholder value not flagged" (@($hits | Where-Object { $_ -match "placeholder\.txt" }).Count -eq 0)

    # --- 5. personal path detection ---------------------------------------------
    $pp = Join-Path $tmp "pp"; New-Item -ItemType Directory $pp | Out-Null
    $winUser  = 'C:' + '\Users\ean\Documents\report.docx'
    $unixHome = '/ho' + 'me/alice/build.log'
    Set-Content (Join-Path $pp "a.txt") "see $winUser"
    Set-Content (Join-Path $pp "b.txt") "logs at $unixHome"
    Set-Content (Join-Path $pp "c.txt") "portable relative path ./data"
    $phits = @(Find-PersonalPaths $pp)
    Assert "Windows user path detected"  (@($phits | Where-Object { $_ -match "a\.txt" -and $_ -match "Windows user path" }).Count -gt 0)
    Assert "Unix home path detected"     (@($phits | Where-Object { $_ -match "b\.txt" -and $_ -match "Unix home path" }).Count -gt 0)
    Assert "relative path not flagged"   (@($phits | Where-Object { $_ -match "c\.txt" }).Count -eq 0)

    # --- 6. GitHub slug parsing -------------------------------------------------
    Assert "https URL parsed"    ((ConvertTo-GithubSlug "https://github.com/ean/api.git") -eq "ean/api")
    Assert "ssh URL parsed"      ((ConvertTo-GithubSlug "git@github.com:ean/api.git") -eq "ean/api")
    Assert "trailing slash ok"   ((ConvertTo-GithubSlug "https://github.com/ean/api/") -eq "ean/api")
    Assert "non-github ignored"  ((ConvertTo-GithubSlug "https://gitlab.com/ean/api.git") -eq "")
    Assert "empty URL ignored"   ((ConvertTo-GithubSlug "") -eq "")

    # --- 7. launch checklist ----------------------------------------------------
    $items = @(New-Checklist -IsRepo $false -Files @{ Readme=""; License=""; Gitignore=""; Metadata="" } `
                             -Secrets @("x") -Paths @() -EnvNote "" -PendingGuards @())
    Assert "checklist: git init suggested"    (@($items | Where-Object { $_ -match "git init" }).Count -eq 1)
    Assert "checklist: license suggested"     (@($items | Where-Object { $_ -match "LICENSE" }).Count -eq 1)
    Assert "checklist: gitignore suggested"   (@($items | Where-Object { $_ -match "\.gitignore" }).Count -eq 1)
    Assert "checklist: secret item present"   (@($items | Where-Object { $_ -match "secret" }).Count -ge 1)
    $items2 = @(New-Checklist -IsRepo $true -Files @{ Readme="README.md"; License="LICENSE"; Gitignore=".gitignore"; Metadata="package.json" } `
                              -Secrets @() -Paths @() -EnvNote "" -PendingGuards @())
    Assert "checklist: complete repo gets a single all-clear line" ($items2.Count -eq 1)

    # --- 8. integration: the real script, dry run -------------------------------
    if (Test-CommandAvailable "git") {
        & (Join-Path $PSScriptRoot "..\launch-kit.ps1") -Path $full *> $null
        Assert "dry-run on non-repo folder exits 1" ($LASTEXITCODE -eq 1)
        & (Join-Path $PSScriptRoot "..\launch-kit.ps1") -Path $repo *> $null
        Assert "dry-run on repo fixture exits 0" ($LASTEXITCODE -eq 0)
        Assert "dry-run wrote no checklist file" (-not (Test-Path (Join-Path $repo "LAUNCH-CHECKLIST.md")))
    }
}
finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
if ($script:fail -gt 0) { Write-Host "$($script:fail) test(s) failed"; exit 1 }
Write-Host "all $script:pass tests passed"
