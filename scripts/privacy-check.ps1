[CmdletBinding()]
param([string]$GitleaksPath)
. (Join-Path $PSScriptRoot 'common.ps1')
Push-Location $ProjectRoot
try {
    $tracked = @(& git ls-files)
    if ($LASTEXITCODE -ne 0 -or $tracked.Count -eq 0) { throw 'No staged or tracked files to check.' }
    $errors = [Collections.Generic.List[string]]::new()
    foreach ($relative in $tracked) {
        if ($relative -match '^(data|build|dist|\.vs|\.codex|\.agents)/' -or $relative -match '\.(exe|pdb|dmp|log|pem|key)$') {
            $errors.Add("File must be excluded: $relative")
            continue
        }
        $content = [IO.File]::ReadAllText((Join-Path $ProjectRoot $relative))
        # Concatenated pattern fragments avoid matching the checker itself.
        $privatePathPattern = '[A-Z]:[\\/]' + 'Users[\\/][^\s\\/]+'
        if ($content -match $privatePathPattern) { $errors.Add("Personal profile path: $relative") }
        $secretPattern = 'gh' + '[opusr]_[A-Za-z0-9]{20,}|github' + '_pat_[A-Za-z0-9_]{20,}|-----BEGIN ' + '(RSA |EC |OPENSSH )?PRIVATE KEY-----'
        if ($content -match $secretPattern) { $errors.Add("Possible secret: $relative") }
        foreach ($match in [regex]::Matches($content, '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')) {
            if ($match.Value -ne 'dev@scaping.invalid') { $errors.Add("Nontechnical email address: $relative") }
        }
    }
    $commits = @(& git log --all '--format=%an|%ae|%cn|%ce' 2>$null)
    foreach ($identity in $commits) {
        if ($identity -ne 'Scaping Development|dev@scaping.invalid|Scaping Development|dev@scaping.invalid') { $errors.Add('Nontechnical commit identity.') }
    }
    if ($errors.Count) { throw ($errors -join [Environment]::NewLine) }
    if ($GitleaksPath) {
        Invoke-Checked $GitleaksPath @('git', $ProjectRoot, '--staged', '--redact', '--no-banner')
        if ($commits.Count) { Invoke-Checked $GitleaksPath @('git', $ProjectRoot, '--redact', '--no-banner') }
    }
    Write-Host "Privacy checks passed: $($tracked.Count) tracked files; $($commits.Count) commits."
} finally { Pop-Location }
