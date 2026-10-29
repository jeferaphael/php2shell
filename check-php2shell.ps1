<#
.SYNOPSIS
    check-php2shell.ps1 — VÉRIFICATION SEULE (LECTURE SEULE : ne modifie rien).

.DESCRIPTION
    Dit s'il y a PHP ou non ; si oui, liste les versions et indique si elles sont
    vulnérables à chacune des deux failles PHP2Shell :
      . CVE-2026-109618 — Corruption mémoire lors de la gestion de l'OOM (RCE non authentifiée)
      . CVE-2026-109619 — Use-after-free dans session.upload_progress (RCE + fuite mémoire)
    Puis donne la mesure corrective (exécuter le script de correction).
    Si PHP est ABSENT, affiche les autres technologies présentes (Node.js, Python,
    Java, .NET/ASP.NET, Ruby, Go...) avec leurs versions.

    Versions corrigées (ferment les DEUX CVE) : 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35.
    Branches EOL (8.1 / 8.0 / 7.x) : aucun correctif officiel -> durcir + migrer.

.NOTES
    Lecture seule : ne nécessite pas d'être administrateur (mais l'élévation permet
    de voir toutes les installations). Codes de sortie : 0 = tout corrigé ;
    1 = au moins une install vulnérable ; 2 = aucun PHP détecté.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'SilentlyContinue'
$FixScript = '.\fix-php2shell-v6.ps1'

function Get-FixedFor { param($mm)
    switch ($mm) { '8.5'{'8.5.12'} '8.4'{'8.4.27'} '8.3'{'8.3.36'} '8.2'{'8.2.35'} default{''} }
}
function Test-VerGe { param($have,$want)
    try { return ([version]$have) -ge ([version]$want) } catch { return $false }
}
function Get-VerFromText { param($txt)
    if (-not $txt) { return '' }
    $m = [regex]::Match(($txt -join "`n"), '(\d+\.\d+\.\d+)')
    if ($m.Success) { return $m.Groups[1].Value }
    return ''
}

# --- Découverte EXHAUSTIVE des php.exe (Plesk + stacks + racines ciblées) ---
function Get-PhpExes {
    $cands = @()
    $cands += (Get-Command php.exe -EA SilentlyContinue | Select-Object -Expand Source)

    foreach ($k in @('HKLM:\SOFTWARE\Plesk\Psa Config\Config',
                     'HKLM:\SOFTWARE\WOW6432Node\Plesk\Psa Config\Config')) {
        try {
            $p = (Get-ItemProperty -Path $k -EA Stop).PRODUCT_ROOT_D
            if ($p -and (Test-Path $p)) {
                Get-ChildItem (Join-Path $p 'Additional') -Directory -Filter 'PleskPHP*' -EA SilentlyContinue |
                    ForEach-Object { $e = Join-Path $_.FullName 'php.exe'; if (Test-Path $e) { $cands += $e } }
            }
        } catch {}
    }

    $drives = [System.IO.DriveInfo]::GetDrives() |
              Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady } |
              ForEach-Object { $_.RootDirectory.FullName }
    foreach ($d in $drives) {
        Get-ChildItem -LiteralPath $d -Directory -EA SilentlyContinue | ForEach-Object {
            $base = $_.FullName
            foreach ($c in @((Join-Path $base 'php.exe'), (Join-Path $base 'php\php.exe'))) {
                if (Test-Path -LiteralPath $c) { $cands += $c }
            }
            foreach ($bp in @('bin\php','bin\php\php')) {
                $bpp = Join-Path $base $bp
                if (Test-Path -LiteralPath $bpp) {
                    Get-ChildItem -LiteralPath $bpp -Directory -Filter 'php*' -EA SilentlyContinue |
                        ForEach-Object { $e = Join-Path $_.FullName 'php.exe'; if (Test-Path -LiteralPath $e) { $cands += $e } }
                }
            }
        }
    }

    $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData,
               'C:\tools', 'C:\laragon', 'C:\inetpub')
    foreach ($d in $drives) { $roots += @((Join-Path $d 'php'), (Join-Path $d 'laragon')) }
    foreach ($r in ($roots | Where-Object { $_ } | Select-Object -Unique)) {
        if (Test-Path -LiteralPath $r) {
            try { Get-ChildItem -LiteralPath $r -Recurse -Depth 4 -Filter 'php.exe' -File -EA SilentlyContinue |
                    ForEach-Object { $cands += $_.FullName } } catch {}
        }
    }
    # Balayage borné de chaque lecteur fixe (hors dossiers système), pour un PHP
    # rangé dans un chemin applicatif quelconque (ex. D:\new sts6\Apache\bin\php.exe).
    $skipTop = @('Windows','$Recycle.Bin','System Volume Information','Recovery',
                 'PerfLogs','$WinREAgent','MSOCache')
    foreach ($d in $drives) {
        Get-ChildItem -LiteralPath $d -Directory -EA SilentlyContinue |
            Where-Object { $skipTop -notcontains $_.Name } | ForEach-Object {
                try {
                    Get-ChildItem -LiteralPath $_.FullName -Recurse -Depth 5 -Filter 'php.exe' -File -EA SilentlyContinue |
                        ForEach-Object { $cands += $_.FullName }
                } catch { }
            }
    }
    return ($cands | Where-Object { $_ } | Select-Object -Unique)
}

# --- Version PHP : plusieurs méthodes, on garde la première qui répond ------
function Get-PhpVersion { param($php)
    if (Test-Path -LiteralPath $php) {
        foreach ($a in @(@('-v'), @('-n','-v'), @('-n','-r','echo PHP_VERSION;'))) {
            try { $v = Get-VerFromText (& $php @a 2>$null); if ($v) { return $v } } catch {}
        }
        try {
            $info = (Get-Item -LiteralPath $php).VersionInfo
            foreach ($pv in @($info.ProductVersion, $info.FileVersion)) {
                $v = Get-VerFromText ([string]$pv); if ($v) { return $v }
            }
        } catch {}
        $dir = Split-Path $php
        foreach ($cfg in @((Join-Path $dir 'php.ini'), (Join-Path (Split-Path $dir) 'RELEASENOTES'))) {
            if (Test-Path -LiteralPath $cfg) {
                $v = Get-VerFromText (Get-Content -LiteralPath $cfg -TotalCount 80 -EA SilentlyContinue)
                if ($v) { return $v }
            }
        }
    }
    return ''
}

# --- Autres technologies (affiché si PHP absent) ---------------------------
function Show-Tech { param($Label, $Cmd, [string[]]$CArgs)
    if (Get-Command $Cmd -EA SilentlyContinue) {
        $v = (& $Cmd @CArgs 2>&1 | Select-Object -First 1)
        Write-Host ("  - {0} : {1}" -f $Label, ("$v" -replace '\r',''))
    }
}
function Detect-OtherStacks {
    Write-Host ""
    Write-Host "Autres technologies détectées sur le serveur :" -ForegroundColor Cyan
    Show-Tech 'Node.js' 'node'   @('-v')
    Show-Tech 'npm'     'npm'    @('-v')
    Show-Tech 'Python'  'python' @('--version')
    Show-Tech 'Python'  'py'     @('--version')
    if (Get-Command python -EA SilentlyContinue) {
        $dj = (& python -c "import django;print(django.get_version())" 2>$null)
        if ($dj) { Write-Host "  - Django : $dj" }
    }
    Show-Tech 'Java'    'java'   @('-version')
    Show-Tech '.NET SDK/runtime' 'dotnet' @('--version')
    if (Get-Command dotnet -EA SilentlyContinue) {
        $asp = (& dotnet --list-runtimes 2>$null | Select-String 'AspNetCore' | Select-Object -First 1)
        if ($asp) { Write-Host "  - ASP.NET Core : $asp" }
    }
    Show-Tech 'Ruby'    'ruby'   @('-v')
    Show-Tech 'Rails'   'rails'  @('-v')
    Show-Tech 'Go'      'go'     @('version')
    Show-Tech 'Perl'    'perl'   @('-v')
    # IIS + .NET Framework (ASP.NET « classique »)
    if (Get-Service W3SVC -EA SilentlyContinue) {
        Write-Host "  - IIS : présent (service W3SVC)"
        try {
            $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -EA Stop).Version
            if ($v) { Write-Host "  - .NET Framework : $v" }
        } catch {}
    }
    $ap = Get-Service -EA SilentlyContinue |
          Where-Object { $_.Name -match 'apache|wampapache' -or $_.DisplayName -match 'Apache' } |
          Select-Object -First 1
    if ($ap) { Write-Host ("  - Apache : service {0}" -f $ap.Name) }
}

# =========================================================================
Write-Host ""
Write-Host "=== Vérification PHP2Shell (CVE-2026-109618 / CVE-2026-109619) — LECTURE SEULE ===" -ForegroundColor Cyan
Write-Host "Aucune modification ne sera faite. Ce script ne fait que constater."

$exes = @(Get-PhpExes | Where-Object { (Split-Path $_ -Leaf) -ieq 'php.exe' })

if ($exes.Count -eq 0) {
    Write-Host ""
    Write-Host "PHP : ABSENT." -ForegroundColor Green
    Write-Host "-> Rien à corriger pour PHP2Shell (les CVE 109618/109619 ne concernent que PHP)."
    Detect-OtherStacks
    exit 2
}

Write-Host ""
Write-Host ("PHP : PRÉSENT — {0} installation(s) détectée(s)." -f $exes.Count) -ForegroundColor Cyan

$vuln = 0; $ok = 0
foreach ($php in $exes) {
    $ver = Get-PhpVersion $php; if (-not $ver) { $ver = '?' }
    $mm  = if ($ver -ne '?') { ($ver -split '\.')[0..1] -join '.' } else { '' }
    $fixed = Get-FixedFor $mm

    if ($fixed) {
        if (($ver -ne '?') -and (Test-VerGe $ver $fixed)) {
            $state = 'OK'; $verdict = "NON vulnérable — corrigé (version >= $fixed)"; $col = 'Green'
        } else {
            $state = 'VULN'; $verdict = "VULNÉRABLE — correctif disponible : mettre à jour vers $fixed"; $col = 'Red'
        }
    } else {
        $state = 'EOL'; $verdict = "VULNÉRABLE — branche en fin de vie, aucun correctif officiel"; $col = 'Red'
    }

    # État des mesures d'atténuation (lecture seule des ini effectifs).
    $up  = "$(& $php -r "echo (int)ini_get('session.upload_progress.enabled');" 2>$null)".Trim()
    $mem = "$(& $php -r "echo trim(ini_get('memory_limit'));" 2>$null)".Trim()
    # « en place » = vert (mesure compensatoire présente) ; « ABSENTE » = rouge.
    if ($mem -eq '-1') { $a618 = 'en place'; $c618 = 'Green' } else { $a618 = 'ABSENTE'; $c618 = 'Red' }
    if ($up  -eq '0')  { $a619 = 'en place'; $c619 = 'Green' } else { $a619 = 'ABSENTE'; $c619 = 'Red' }

    Write-Host ""
    Write-Host "--------------------------------------------------------------------"
    Write-Host ("Chemin  : {0}" -f $php)
    Write-Host ("Version : {0}   (branche php{1})" -f $ver, $mm)
    Write-Host "CVE-2026-109618 — Corruption mémoire (OOM) :" -NoNewline; Write-Host (" {0}" -f $verdict) -ForegroundColor $col
    Write-Host "   atténuation memory_limit=-1 .............. " -NoNewline; Write-Host $a618 -ForegroundColor $c618
    Write-Host "CVE-2026-109619 — Use-after-free (upload_progress) :" -NoNewline; Write-Host (" {0}" -f $verdict) -ForegroundColor $col
    Write-Host "   atténuation session.upload_progress=0 .... " -NoNewline; Write-Host $a619 -ForegroundColor $c619

    if ($state -eq 'OK') { $ok++ } else { $vuln++ }
}

Write-Host ""
Write-Host "--------------------------------------------------------------------"
Write-Host ("BILAN : {0} corrigée(s), {1} vulnérable(s) sur {2}." -f $ok, $vuln, $exes.Count)

if ($vuln -gt 0) {
    Write-Host ""
    Write-Host "MESURE CORRECTIVE :" -ForegroundColor Yellow
    Write-Host "  Veuillez exécuter le script de correction pour fixer la vulnérabilité :"
    Write-Host ("      $FixScript")
    Write-Host "  (ou double-cliquez sur LANCER-correctif.bat). Il met à jour PHP vers la"
    Write-Host "  version corrigée (ferme les 2 CVE) et applique le durcissement. Pour les"
    Write-Host "  branches EOL, il durcit en attendant la migration (viser 8.3 / 8.4)."
    exit 1
}

Write-Host ""
Write-Host "Toutes les installations PHP sont à une version corrigée. Rien à faire." -ForegroundColor Green
exit 0
