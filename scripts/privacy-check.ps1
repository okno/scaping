[CmdletBinding()]
param([string]$GitleaksPath)
. (Join-Path $PSScriptRoot 'common.ps1')
Push-Location $ProjectRoot
try {
    $tracked = @(& git ls-files)
    if ($LASTEXITCODE -ne 0 -or $tracked.Count -eq 0) { throw 'Nessun file staged/tracciato da controllare.' }
    $errors = [Collections.Generic.List[string]]::new()
    foreach ($relative in $tracked) {
        if ($relative -match '^(data|build|dist|\.vs|\.codex|\.agents)/' -or $relative -match '\.(exe|pdb|dmp|log|pem|key)$') {
            $errors.Add("File da escludere: $relative")
            continue
        }
        $content = [IO.File]::ReadAllText((Join-Path $ProjectRoot $relative))
        # Concatenated pattern fragments avoid matching the checker itself.
        $privatePathPattern = '[A-Z]:[\\/]' + 'Users[\\/][^\s\\/]+'
        if ($content -match $privatePathPattern) { $errors.Add("Percorso profilo personale: $relative") }
        $secretPattern = 'gh' + '[opusr]_[A-Za-z0-9]{20,}|github' + '_pat_[A-Za-z0-9_]{20,}|-----BEGIN ' + '(RSA |EC |OPENSSH )?PRIVATE KEY-----'
        if ($content -match $secretPattern) { $errors.Add("Possibile segreto: $relative") }
        foreach ($match in [regex]::Matches($content, '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')) {
            if ($match.Value -ne 'dev@scaping.invalid') { $errors.Add("Indirizzo non tecnico: $relative") }
        }
    }
    $commits = @(& git log --all '--format=%an|%ae|%cn|%ce' 2>$null)
    foreach ($identity in $commits) {
        if ($identity -ne 'Scaping Development|dev@scaping.invalid|Scaping Development|dev@scaping.invalid') { $errors.Add('Identita commit non tecnica.') }
    }
    if ($errors.Count) { throw ($errors -join [Environment]::NewLine) }
    if ($GitleaksPath) {
        Invoke-Checked $GitleaksPath @('git', $ProjectRoot, '--staged', '--redact', '--no-banner')
        if ($commits.Count) { Invoke-Checked $GitleaksPath @('git', $ProjectRoot, '--redact', '--no-banner') }
    }
    Write-Host "Controlli privacy superati: $($tracked.Count) file tracciati; $($commits.Count) commit."
} finally { Pop-Location }
