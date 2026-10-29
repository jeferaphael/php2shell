<#
.SYNOPSIS
    Atténue et corrige PHP2Shell (CVE-2026-109618 / CVE-2026-109619) sur un
    serveur Windows, avec prise en charge des handlers PHP de Plesk.

.DESCRIPTION
    Version PowerShell du correctif, même démarche que la version Linux :
      1. DURCISSEMENT  : session.upload_progress.enabled = 0 dans chaque php.ini
                         (atténuation immédiate du vecteur connu) + sauvegardes.
      2. PATCH PLESK   : plesk installer sur chaque handler PHP installé.
      3. RECYCLAGE IIS : les handlers PHP tournent en FastCGI sous IIS ; un
                         recyclage est nécessaire pour recharger php.ini.
      4. VERIFICATION  : rapport versions / version attendue / patch / durci.

    Versions corrigées de référence : 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35
    Branches EOL (7.4 / 8.0 / 8.1) : pas de release upstream, seulement des
    backports éditeur -> le script NE garantit PAS le correctif par le numéro de
    version et le signale (EOL?). Le durcissement reste la protection active.

    Volet CVE-2026-109619 (use-after-free) : session.upload_progress.enabled = 0 (toujours).
    Volet CVE-2026-109618 (corruption OOM) : memory_limit = -1.
      -> ACTIVÉ PAR DÉFAUT (désactivable via -NoMemoryUnlimited).
         Les limites d'upload (upload_max_filesize / post_max_size) NE sont PAS
         modifiées par défaut : l'existant est PRÉSERVÉ (ne casse aucun upload).
         -RequestLimit X impose upload=X et post=+25 %.
         NB : memory_limit=-1 est une atténuation PLAUSIBLE mais NON confirmée par
         l'éditeur -> « appliquée » n'est pas « prouvée ».

.PARAMETER DryRun
    Simulation : affiche les actions sans rien modifier.
.PARAMETER HardenOnly
    N'exécute que l'étape 1 (durcissement).
.PARAMETER NoPlesk
    Saute l'étape Plesk (utile pour un PHP autonome hors Plesk).
.PARAMETER RequestLimit
    Impose upload_max_filesize = X et post_max_size = +25 %. Non fourni -> limites préservées.
.PARAMETER NoMemoryUnlimited
    Désactive le volet 618 (ne pose PAS memory_limit = -1). Par défaut, le volet est ACTIF.
.PARAMETER DisableFunctions
    Pose disable_functions = exec,shell_exec,... (réduit la surface ; peut casser une appli).

.EXAMPLE
    .\fix-php2shell-v7.ps1
    Exécution complète en un seul coup : durcissement + patch (Plesk si présent)
    + redémarrage du serveur web + résumé par CVE. C'est l'usage normal.
.EXAMPLE
    .\fix-php2shell-v7.ps1 -NoMemoryUnlimited
    Revient au seul volet 109619 (sûr) sans poser memory_limit = -1.
.NOTES
    À lancer en ADMINISTRATEUR. Le plus simple : double-cliquer sur
    « LANCER-correctif.bat » fourni à côté (auto-élévation + exécution).
#>
[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$HardenOnly,
    [switch]$NoPlesk,
    [string]$RequestLimit = '',
    [switch]$NoMemoryUnlimited,
    [switch]$DisableFunctions,
    [switch]$NoExposePhpOff
)

$ErrorActionPreference = 'Stop'
$ts     = Get-Date -Format 'yyyyMMdd-HHmmss'
$log    = Join-Path $env:TEMP "fix-php2shell-$ts.log"
$marker = 'CVE-2026-109618 / CVE-2026-109619 (PHP2Shell)'

# --- Journalisation -------------------------------------------------------
function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'HH:mm:ss'), $Level, $Msg
    $color = switch ($Level) { 'OK'{'Green'} 'WARN'{'Yellow'} 'ERR'{'Red'} default{'Cyan'} }
    Write-Host $line -ForegroundColor $color
    Add-Content -Path $log -Value $line
}
function Invoke-Step {
    param([scriptblock]$Action, [string]$Describe)
    if ($DryRun) { Write-Log "  (dry-run) $Describe" 'INFO'; return }
    & $Action
}

# --- Contrôle élévation ---------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "À lancer dans une console PowerShell ELEVÉE (administrateur)." 'ERR'
    exit 1
}
Write-Log "Journal : $log"
if ($DryRun) { Write-Log "MODE SIMULATION : aucune modification ne sera écrite." 'WARN' }

# --- Résolution des options de durcissement + garde-fou 109618 ------------
$ApplyExposePhpOff   = -not $NoExposePhpOff
# Volet 618 ACTIVÉ PAR DÉFAUT : memory_limit=-1. Désactivable via -NoMemoryUnlimited.
# Limites d'upload : sans -RequestLimit, on PRÉSERVE celles déjà en place (choix de
# l'admin = plafond de requête existant). memory_limit=-1 s'y appuie ; rien n'est
# plafonné en plus. Pour imposer/baisser un plafond : -RequestLimit (ex. 64M).
$MemoryUnlimited     = -not $NoMemoryUnlimited
$DisableFuncs        = 'exec,passthru,shell_exec,system,proc_open,popen'
if ($MemoryUnlimited -and -not $RequestLimit) {
    Write-Log "Pas de -RequestLimit : upload_max_filesize / post_max_size laissés INCHANGÉS (existant préservé)." 'INFO'
    Write-Log "memory_limit=-1 s'appuie sur les plafonds de requête déjà configurés. Forcer un plafond : -RequestLimit 32M." 'INFO'
}

# Construit le bloc de durcissement (marqueurs -> ré-application idempotente).
# Sépare les deux CVE : 109619 (session.upload_progress) / 109618 (memory_limit + plafonds).
# Calcule post_max_size à partir de -RequestLimit : +25 % (même unité), arrondi au
# supérieur, pour que post_max_size > upload_max_filesize (sinon un fichier à la
# taille max + les champs du formulaire dépassent post_max_size -> refus).
# Ex : 32M -> 40M, 64M -> 80M. Format inattendu -> valeur inchangée (repli sûr).
function Get-PostFromReq {
    param([string]$v)
    if ($v -match '^(\d+)([KkMmGg]?)$') {
        $num  = [int]$matches[1]
        $unit = $matches[2]
        return ('{0}{1}' -f [int][math]::Ceiling($num * 1.25), $unit)
    }
    return $v
}

function Get-HardeningBlock {
    $nl = "`r`n"
    $b  = "; >>> Durcissement PHP2Shell (CVE-2026-109618 / CVE-2026-109619) - $ts >>>$nl"
    $b += "; --- CVE-2026-109619 (use-after-free) : attenuation ---$nl"
    $b += "session.upload_progress.enabled = 0$nl"
    if ($ApplyExposePhpOff) {
        $b += "; --- Hygiene : ne pas divulguer la version de PHP ---$nl"
        $b += "expose_php = Off$nl"
    }
    if ($RequestLimit -or $MemoryUnlimited -or $DisableFunctions) {
        $b += "; --- CVE-2026-109618 (corruption lors du OOM) : attenuation ---$nl"
    }
    if ($RequestLimit) {
        $b += "upload_max_filesize = $RequestLimit$nl"
        $b += "post_max_size = $(Get-PostFromReq $RequestLimit)$nl"   # +25 % > upload
    }
    if ($MemoryUnlimited)   { $b += "memory_limit = -1$nl" }
    if ($DisableFunctions)  { $b += "disable_functions = $DisableFuncs$nl" }
    $b += "; <<< Durcissement PHP2Shell <<<$nl"
    return $b
}

# --- Localisation de Plesk ------------------------------------------------
function Get-PleskDir {
    foreach ($k in @('HKLM:\SOFTWARE\Plesk\Psa Config\Config',
                     'HKLM:\SOFTWARE\WOW6432Node\Plesk\Psa Config\Config')) {
        try {
            $p = (Get-ItemProperty -Path $k -ErrorAction Stop).PRODUCT_ROOT_D
            if ($p -and (Test-Path $p)) { return $p }
        } catch { }
    }
    if ($env:plesk_dir -and (Test-Path $env:plesk_dir)) { return $env:plesk_dir }
    return $null
}
$pleskDir = Get-PleskDir
$pleskBin = if ($pleskDir) { Join-Path $pleskDir 'admin\bin\plesk.exe' } else { $null }
$hasPlesk = $pleskDir -and (Test-Path $pleskBin)

# --- Découverte des php.ini (handlers Plesk + PHP autonome) ---------------
function Get-PhpInstalls {
    # Retourne des objets : @{ Ini=<php.ini>; Php=<php.exe>; Label=<texte> }
    $found = @{}

    # 1) Handlers Plesk : scan disque ...\Plesk\Additional\PleskPHP*\
    #    (chemins fiables même avec des espaces ; c'est le php.ini global du handler,
    #     celui qui porte le réglage de sécurité au niveau serveur).
    if ($hasPlesk) {
        $add = Join-Path $pleskDir 'Additional'
        if (Test-Path $add) {
            Get-ChildItem $add -Directory -Filter 'PleskPHP*' -EA SilentlyContinue | ForEach-Object {
                $ini = Join-Path $_.FullName 'php.ini'
                $php = Join-Path $_.FullName 'php.exe'
                if ((Test-Path $ini) -and -not $found.ContainsKey($ini)) {
                    $found[$ini] = @{ Ini=$ini; Php=$php; Label="plesk $($_.Name)" }
                }
            }
        }
    }

    # 2) PHP autonome : PATH + emplacements courants.
    #    IMPORTANT : pas de -Recurse ici. Sous PowerShell 5.1, un joker dans -Path
    #    combiné à -Recurse ignore -Depth et balaie TOUT le disque (script figé).
    #    On énumère donc uniquement les dossiers "php*" de 1er niveau, sans récursion.
    #    Couvre aussi les stacks XAMPP / WAMP / MAMP, sur TOUS les lecteurs fixes.
    $cands = @()
    $cands += (Get-Command php.exe -EA SilentlyContinue | Select-Object -Expand Source)

    $drives = [System.IO.DriveInfo]::GetDrives() |
              Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady } |
              ForEach-Object { $_.RootDirectory.FullName }

    foreach ($d in $drives) {
        Get-ChildItem -LiteralPath $d -Directory -EA SilentlyContinue | ForEach-Object {
            $base = $_.FullName
            # a) PHP a la racine du dossier : <base>\php.exe        (ex: D:\php)
            # b) Dossier "php" (XAMPP)      : <base>\php\php.exe    (ex: D:\xampp\php)
            foreach ($cand in @((Join-Path $base 'php.exe'), (Join-Path $base 'php\php.exe'))) {
                if (Test-Path -LiteralPath $cand) { $cands += $cand }
            }
            # c) WAMP / MAMP / Laragon (versions multiples) : <base>\bin\php\php*\php.exe
            foreach ($bp in @('bin\php','bin\php\php')) {
                $binphp = Join-Path $base $bp
                if (Test-Path -LiteralPath $binphp) {
                    Get-ChildItem -LiteralPath $binphp -Directory -Filter 'php*' -EA SilentlyContinue |
                        ForEach-Object {
                            $e = Join-Path $_.FullName 'php.exe'
                            if (Test-Path -LiteralPath $e) { $cands += $e }
                        }
                }
            }
        }
    }

    # 3) Recherche bornée (profondeur limitée) sur des racines ciblées, pour les
    #    installs rangées hors des emplacements standards. -LiteralPath évite le
    #    piège PS 5.1 (joker + -Recurse ignore -Depth et balaie tout le disque).
    $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData,
               'C:\tools', 'C:\laragon', 'C:\inetpub')
    foreach ($d in $drives) { $roots += @((Join-Path $d 'php'), (Join-Path $d 'laragon')) }
    foreach ($r in ($roots | Where-Object { $_ } | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $r)) { continue }
        try {
            Get-ChildItem -LiteralPath $r -Recurse -Depth 4 -Filter 'php.exe' -File -EA SilentlyContinue |
                ForEach-Object { $cands += $_.FullName }
        } catch { }
    }

    # 4) Balayage borné de CHAQUE lecteur fixe, dossier de 1er niveau par dossier
    #    (hors dossiers système lourds), pour un PHP rangé dans un chemin applicatif
    #    quelconque — ex. D:\new sts6\Apache\bin\php.exe, que les motifs ci-dessus
    #    ne couvrent pas. On recurse sur un dossier CONCRET via -LiteralPath (pas de
    #    joker -> pas le piège PS 5.1) et -Depth borne le temps de parcours.
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

    # Pour chaque php.exe, durcir le(s) php.ini concerne(s).
    # WAMP distingue php.ini (CLI) et phpForApache.ini (Apache) -> on prend les deux.
    foreach ($php in ($cands | Where-Object { $_ } | Select-Object -Unique)) {
        $dir  = Split-Path $php
        $leaf = Split-Path $dir -Leaf
        $added = $false
        foreach ($n in @('php.ini','phpForApache.ini')) {
            $ini = Join-Path $dir $n
            if (Test-Path -LiteralPath $ini) {
                if (-not $found.ContainsKey($ini)) {
                    $found[$ini] = @{ Ini=$ini; Php=$php; Label="php $leaf ($n)" }
                }
                $added = $true
            }
        }
        # php.exe trouvé mais sans php.ini adjacent : on le signale quand même
        # (visibilité) ; l'install apparaît au rapport mais ne peut pas être durcie ici.
        if ((-not $added) -and (-not $found.ContainsKey($php))) {
            $found[$php] = @{ Ini='(introuvable)'; Php=$php; Label="php $leaf (php.ini introuvable)" }
        }
    }
    return $found.Values
}

# --- 1) DURCISSEMENT ------------------------------------------------------
function Set-Hardening {
    param([hashtable]$Inst)
    $ini     = $Inst.Ini
    $php     = $Inst.Php
    $created = $false

    # php.ini absent : sans fichier, le durcissement n'a nulle part où s'écrire
    # (c'était le cas des 5 installs « php.ini introuvable »). On en crée un à côté
    # du php.exe : copie de php.ini-production si présent (config prod recommandée),
    # sinon un php.ini minimal (PHP garde ses défauts + nos overrides de durcissement).
    if ([string]::IsNullOrWhiteSpace($ini) -or $ini -eq '(introuvable)' -or -not (Test-Path -LiteralPath $ini)) {
        if ([string]::IsNullOrWhiteSpace($php) -or -not (Test-Path -LiteralPath $php)) {
            Write-Log "php.ini et php.exe introuvables : installation ignorée." 'WARN'; return
        }
        $dir = [System.IO.Path]::GetDirectoryName($php)   # dossier parent (robuste, chemins avec espaces OK)
        $ini = Join-Path $dir 'php.ini'
        if ($DryRun) { Write-Log "(dry-run) créerait puis durcirait : $ini" 'OK'; return }
        $prod = Join-Path $dir 'php.ini-production'
        $dev  = Join-Path $dir 'php.ini-development'
        if (Test-Path -LiteralPath $prod) {
            Copy-Item -LiteralPath $prod -Destination $ini -Force
            Write-Log "php.ini absent -> créé depuis php.ini-production : $ini" 'OK'
        } elseif (Test-Path -LiteralPath $dev) {
            Copy-Item -LiteralPath $dev -Destination $ini -Force
            Write-Log "php.ini absent -> créé depuis php.ini-development : $ini" 'OK'
        } else {
            Set-Content -LiteralPath $ini -Value "; php.ini créé par fix-php2shell (aucun modèle présent) - durcissement seul`r`n"
            Write-Log "php.ini absent -> créé (minimal) : $ini" 'OK'
        }
        $created   = $true
        $Inst.Ini  = $ini    # le rapport relira la config au bon endroit ensuite
    }

    if ($DryRun) { Write-Log "(dry-run) durcirait : $ini" 'OK'; return }
    $content = Get-Content -LiteralPath $ini -Raw -EA SilentlyContinue
    if ($null -eq $content) { $content = '' }
    # Sauvegarde uniquement si le fichier préexistait (inutile pour un fichier qu'on vient de créer).
    if (-not $created) { Copy-Item -LiteralPath $ini -Destination "$ini.bak-$ts" -Force }
    # Retire tout ancien bloc marqué (ré-application propre), puis ajoute le nouveau
    # en fin de fichier -> ses directives priment (dernière valeur lue par PHP).
    $content = [regex]::Replace($content,
               '(?s);\s*>>> Durcissement PHP2Shell.*?;\s*<<< Durcissement PHP2Shell <<<\s*', '')
    $new = $content.TrimEnd() + "`r`n`r`n" + (Get-HardeningBlock)
    # Pas de -Encoding explicite : compatible 5.1 (ANSI) comme 7.x (utf8NoBOM),
    # tous deux corrects pour un php.ini ; 'Default' planterait sous PowerShell 7.
    Set-Content -LiteralPath $ini -Value $new
    $note = if ($created) { '(nouveau fichier)' } else { "(backup $ini.bak-$ts)" }
    Write-Log "durci : $ini $note" 'OK'
}

# --- 2) PATCH PLESK -------------------------------------------------------
function Update-PleskPhp {
    if (-not $hasPlesk) {
        Write-Log "Pas de Plesk : aucun patch automatique des versions PHP possible." 'WARN'
        Write-Log "XAMPP / WAMP / MAMP / PHP autonome -> mise a jour MANUELLE : remplacer le dossier PHP par un build corrige (>= 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12) depuis windows.php.net. Le durcissement reste la protection active." 'WARN'
        return
    }
    Write-Log "=== Étape 2 : patch des handlers PHP Plesk ===" 'INFO'
    # Versions majeures présentes -> composants phpXY
    $vers = @()
    if (Test-Path (Join-Path $pleskDir 'Additional')) {
        Get-ChildItem (Join-Path $pleskDir 'Additional') -Directory -Filter 'PleskPHP*' -EA SilentlyContinue |
            ForEach-Object {
                if ($_.Name -match 'PleskPHP(\d)(\d+)') { $vers += "$($matches[1]).$($matches[2])" }
            }
    }
    foreach ($v in ($vers | Select-Object -Unique)) {
        $comp = 'php' + $v
        Write-Log "Mise à jour composant Plesk : $comp" 'INFO'
        Invoke-Step -Describe "$pleskBin installer --select-release-current --install-component $comp" -Action {
            & $pleskBin installer --select-release-current --install-component $comp 2>&1 |
                Add-Content -Path $log
        }
    }
    Write-Log "Patch Plesk terminé." 'OK'
}

# --- 3) REDEMARRAGE DU SERVEUR WEB (application du php.ini) ----------------
function Restart-Web {
    Write-Log "=== Étape 3 : redémarrage du serveur web (application du durcissement) ===" 'INFO'
    $restarted = $false

    # Apache (XAMPP / WAMP / MAMP / Apache autonome) : redémarrage AUTOMATIQUE
    $apache = @(Get-Service -EA SilentlyContinue |
                Where-Object { $_.Name -match 'apache|wampapache|xampp' -or $_.DisplayName -match 'Apache' })
    foreach ($svc in $apache) {
        $name = $svc.Name
        if ($DryRun) { Write-Log "  (dry-run) Restart-Service $name" 'INFO'; $restarted = $true; continue }
        try {
            Restart-Service -Name $name -Force -EA Stop
            Write-Log "Apache redémarré : $name" 'OK'; $restarted = $true
        } catch {
            Write-Log "Apache détecté ($name) mais non redémarré (droits ? lancé hors service Windows). Redémarre-le via le panneau XAMPP/WAMP." 'WARN'
        }
    }

    # IIS (si présent) : recyclage automatique des pools (applique le php.ini)
    if (Get-Service W3SVC -EA SilentlyContinue) {
        if ($DryRun) { Write-Log "  (dry-run) recyclage des pools IIS" 'INFO'; $restarted = $true }
        else {
            try {
                Import-Module WebAdministration -EA Stop
                Get-ChildItem IIS:\AppPools | Where-Object { $_.State -eq 'Started' } | ForEach-Object {
                    $pool = $_.Name
                    try { Restart-WebAppPool -Name $pool -ErrorAction Stop; $script:restarted = $true }
                    catch { Write-Log "pool non recyclé : $pool" 'WARN' }
                }
                $restarted = $true
                Write-Log "Pools IIS recyclés." 'OK'
            } catch {
                iisreset /noforce | Add-Content -Path $log
                Write-Log "IIS redémarré (iisreset)." 'OK'; $restarted = $true
            }
        }
    }

    if (-not $restarted) {
        Write-Log "Aucun service web redémarré. Si PHP tourne via le panneau XAMPP/WAMP (hors service Windows), redémarre Apache depuis ce panneau pour appliquer le durcissement." 'WARN'
    }
}

# --- 4) VERIFICATION ------------------------------------------------------
function Get-FixedFor { param($mm)
    switch ($mm) { '8.5'{'8.5.12'} '8.4'{'8.4.27'} '8.3'{'8.3.36'} '8.2'{'8.2.35'} default{''} }
}
function Test-VerGe { param($have,$want)  # $have >= $want ?
    try { return ([version]$have) -ge ([version]$want) } catch { return $false }
}
# Extrait "x.y.z" d'un texte (sous-routine)
function Get-VerFromText { param($txt)
    if (-not $txt) { return '' }
    $joined = ($txt -join "`n")
    $m = [regex]::Match($joined, 'PHP\s+(\d+\.\d+\.\d+)')
    if ($m.Success) { return $m.Groups[1].Value }
    $m = [regex]::Match($joined, '\d+\.\d+\.\d+')
    if ($m.Success) { return $m.Value }
    return ''
}
# Version PHP : on essaie TOUTES les méthodes, dans l'ordre, et on garde la 1re qui répond.
function Get-PhpVersion { param($php)
    $dir = Split-Path $php

    # Méthode 1 : exécution CLI (php -v, -n -v, -r). Autoritatif quand ça marche.
    if (Test-Path -LiteralPath $php) {
        $attempts = @()
        $attempts += ,@('-v')
        $attempts += ,@('-n','-v')
        $attempts += ,@('-n','-r','echo PHP_VERSION;')
        $attempts += ,@('-r','echo PHP_VERSION;')
        foreach ($argset in $attempts) {
            try {
                $out = (& $php @argset 2>$null)
                $v = Get-VerFromText $out
                if ($v) { return $v }
            } catch {}
        }
    }

    # Méthode 2 : métadonnées du binaire php.exe (ProductVersion / FileVersion).
    if (Test-Path -LiteralPath $php) {
        try {
            $info = (Get-Item -LiteralPath $php).VersionInfo
            foreach ($pv in @($info.ProductVersion, $info.FileVersion)) {
                $v = Get-VerFromText ([string]$pv)
                if ($v) { return $v }
            }
        } catch {}
    }

    # Méthode 3 : métadonnées d'une DLL PHP du même dossier (php7ts.dll, php8ts.dll, phpX.dll).
    try {
        $dll = Get-ChildItem -LiteralPath $dir -Filter 'php*ts.dll' -EA SilentlyContinue | Select-Object -First 1
        if (-not $dll) { $dll = Get-ChildItem -LiteralPath $dir -Filter 'php?.dll' -EA SilentlyContinue | Select-Object -First 1 }
        if ($dll) {
            $info = $dll.VersionInfo
            foreach ($pv in @($info.ProductVersion, $info.FileVersion)) {
                $v = Get-VerFromText ([string]$pv)
                if ($v) { return $v }
            }
        }
    } catch {}

    # Méthode 4 : fichier de configuration (en-tête du php.ini) + notes XAMPP si présentes.
    $cfgFiles = @(
        (Join-Path $dir 'php.ini'),
        (Join-Path $dir 'phpForApache.ini'),
        (Join-Path (Split-Path $dir) 'RELEASENOTES'),      # <xampp>\RELEASENOTES
        (Join-Path (Split-Path $dir) 'readme_en.txt')      # <xampp>eadme_en.txt
    )
    foreach ($cfg in $cfgFiles) {
        if (Test-Path -LiteralPath $cfg) {
            try {
                $head = Get-Content -LiteralPath $cfg -TotalCount 80 -EA SilentlyContinue
                $v = Get-VerFromText $head
                if ($v) { return $v }
            } catch {}
        }
    }

    return ''
}
function Get-IniUploadProgress { param($ini)
    # Retourne 1 (On = defaut PHP) ou 0 (Off), d'apres la DERNIERE directive active du php.ini
    if (-not (Test-Path -LiteralPath $ini)) { return 1 }
    $val = 1
    foreach ($line in (Get-Content -LiteralPath $ini -EA SilentlyContinue)) {
        if ($line -match '^\s*session\.upload_progress\.enabled\s*=\s*([^\s;]+)') {
            $v = $matches[1].Trim().Trim('"')
            if     ($v -match '^(0|Off|false|no)$')  { $val = 0 }
            elseif ($v -match '^(1|On|true|yes)$')   { $val = 1 }
        }
    }
    return $val
}
function Get-IniMemoryLimit { param($ini)
    # Retourne la DERNIERE valeur active de memory_limit (ex: 128M, -1), ou '' si absente.
    if (-not (Test-Path -LiteralPath $ini)) { return '' }
    $val = ''
    foreach ($line in (Get-Content -LiteralPath $ini -EA SilentlyContinue)) {
        if ($line -match '^\s*memory_limit\s*=\s*([^\s;]+)') { $val = $matches[1].Trim().Trim('"') }
    }
    return $val
}
# Instantane (version + upload_progress) pour une liste d'installations
function Get-Snapshot { param($installs)
    $snap = @{}
    foreach ($i in $installs) {
        # Clé = php.exe (chemin UNIQUE). Indexer par $i.Ini écrasait toutes les
        # installs sans php.ini (clé commune '(introuvable)') -> versions mélangées.
        $snap[$i.Php] = @{ Version = (Get-PhpVersion $i.Php); Up = (Get-IniUploadProgress $i.Ini) }
    }
    return $snap
}

# Inventaire best-effort des applications web (IIS + Apache), tous stacks.
# Purement informatif (le mapping exact site -> version PHP dépend de la config).
function Get-WebApps {
    Write-Log "=== Applications web détectées (best-effort) ===" 'INFO'
    $any = $false
    # IIS : sites + chemin physique (fiable via WebAdministration)
    if (Get-Service W3SVC -EA SilentlyContinue) {
        try {
            Import-Module WebAdministration -EA Stop
            foreach ($s in (Get-Website -EA SilentlyContinue)) {
                Write-Log ("  [IIS]    {0}   <= site '{1}'" -f $s.physicalPath, $s.name) 'INFO'
                $any = $true
            }
        } catch {}
    }
    # Apache (XAMPP/WAMP/MAMP/autonome) : DocumentRoot + ServerName des vhosts, tous lecteurs.
    $drives = [System.IO.DriveInfo]::GetDrives() |
              Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady } |
              ForEach-Object { $_.RootDirectory.FullName }
    $patterns = @(
        'xampp\apache\conf\extra\httpd-vhosts.conf',
        'xampp\apache\conf\httpd.conf',
        'MAMP\conf\apache\httpd.conf',
        'wamp64\bin\apache\*\conf\extra\httpd-vhosts.conf',
        'wamp\bin\apache\*\conf\extra\httpd-vhosts.conf'
    )
    foreach ($d in $drives) {
        foreach ($p in $patterns) {
            Get-ChildItem -Path (Join-Path $d $p) -EA SilentlyContinue | ForEach-Object {
                $sn = ''
                foreach ($line in (Get-Content -LiteralPath $_.FullName -EA SilentlyContinue)) {
                    if ($line -match '^\s*ServerName\s+(\S+)')    { $sn = $matches[1] }
                    if ($line -match '^\s*DocumentRoot\s+"?([^"]+)"?') {
                        Write-Log ("  [apache] {0}   <= {1}" -f $matches[1].Trim(), $sn) 'INFO'
                        $any = $true
                    }
                }
            }
        }
    }
    if (-not $any) {
        Write-Log "  (aucun site IIS/Apache lisible — stack non standard ou PHP via panneau XAMPP/WAMP)" 'INFO'
    }
}
function Write-Report {
    param($installs, $before)
    Write-Log "=== Résumé détaillé par installation PHP (patch + atténuation, par CVE) ===" 'INFO'
    $sep = '-' * 68
    $recap = @()
    foreach ($i in $installs) {
        $b       = $before[$i.Php]
        $vAvant  = if ($b -and $b.Version) { $b.Version } else { '(non relevé)' }
        $vApres  = Get-PhpVersion $i.Php
        if (-not $vApres) { $vApres = '?' }
        $upA     = Get-IniUploadProgress $i.Ini
        $mem     = Get-IniMemoryLimit $i.Ini
        $mm      = if ($vApres -ne '?') { ($vApres -split '\.')[0..1] -join '.' } else { '' }
        $fixnum  = Get-FixedFor $mm           # version corrigée numérique (ou '' si EOL)
        $fixv    = $fixnum
        if ($fixv) {
            $corr = if (Test-VerGe $vApres $fixv) { "OK — corrigé (version >= $fixv)" }
                    else { "NON — à mettre à jour vers $fixv" }
        } else {
            $corr = "EOL? — branche en fin de vie, aucune version corrigée (migration requise)"
            $fixv = "aucune (branche EOL — viser 8.3 / 8.4)"
        }
        $m618 = if ($mem -eq '-1') { 'Oui — appliquée' } else { 'Non — non appliquée' }
        $m619 = if ($upA -eq 0)    { 'Oui — appliquée' } else { 'Non — non appliquée' }
        $branche = if ($mm) { "php$mm" } else { '?' }

        ''                                                             | Tee-Object -Append $log
        $sep                                                           | Tee-Object -Append $log
        ("Chemin du PHP détecté  : {0}" -f $i.Php)                     | Tee-Object -Append $log
        ("Fichier de config      : {0}" -f $i.Ini)                     | Tee-Object -Append $log
        ("Branche                : {0}" -f $branche)                   | Tee-Object -Append $log
        ("Version AVANT upgrade  : {0}" -f $vAvant)                    | Tee-Object -Append $log
        ("Version APRÈS upgrade  : {0}" -f $vApres)                    | Tee-Object -Append $log
        ("Type / source          : {0}" -f $i.Label)                   | Tee-Object -Append $log
        ''                                                             | Tee-Object -Append $log
        "CVE-2026-109618 — Corruption mémoire lors de la gestion de l'OOM (RCE non authentifiée)" | Tee-Object -Append $log
        ("   . Patch       : Mise à jour de PHP vers la version corrigée ({0})" -f $fixv) | Tee-Object -Append $log
        ("                   -> {0}" -f $corr)                         | Tee-Object -Append $log
        "   . Atténuation : memory_limit = -1 (+ post_max_size / upload_max_filesize)" | Tee-Object -Append $log
        ("                   -> {0}" -f $m618)                         | Tee-Object -Append $log
        "CVE-2026-109619 — Use-after-free dans session.upload_progress (RCE + fuite mémoire)" | Tee-Object -Append $log
        ("   . Patch       : Mise à jour de PHP vers la version corrigée ({0})" -f $fixv) | Tee-Object -Append $log
        ("                   -> {0}" -f $corr)                         | Tee-Object -Append $log
        "   . Atténuation : session.upload_progress.enabled = 0"       | Tee-Object -Append $log
        ("                   -> {0}" -f $m619)                         | Tee-Object -Append $log

        # Données pour le tableau récapitulatif final.
        $inst = (Split-Path (Split-Path $i.Php) -Leaf)
        if ($inst.Length -gt 14) { $inst = $inst.Substring(0,14) }
        if     ($corr -like 'OK*')  { $pstate='Corrigé';    $pcol='Green'; $rem='Aucune (à jour)' }
        elseif ($corr -like 'NON*') { $pstate='Vulnérable'; $pcol='Red';   $rem="Mettre à jour -> $fixnum" }
        else                        { $pstate='Vuln.(EOL)'; $pcol='Red';   $rem='Migrer 8.3/8.4 (durcir)' }
        $a618 = if ($m618 -like 'Oui*') { 'Oui' } else { 'Non' }
        $a619 = if ($m619 -like 'Oui*') { 'Oui' } else { 'Non' }
        $recap += [pscustomobject]@{
            Inst=$inst; Branche=$branche; VA=$vAvant; VP=$vApres;
            Patch=$pstate; PCol=$pcol; Rem=$rem
            A618=$a618; C618=$(if($a618 -eq 'Oui'){'Green'}else{'Red'})
            A619=$a619; C619=$(if($a619 -eq 'Oui'){'Green'}else{'Red'})
        }
    }
    ''                                                                 | Tee-Object -Append $log
    Write-Log "Installations PHP détectées : $($installs.Count)." 'INFO'
    Write-Log "PATCH = seule mesure qui FERME les deux failles (mise à jour de version)." 'INFO'
    Write-Log "ATTÉNUATION = réduit le risque sans corriger (109618 : memory_limit=-1 ; 109619 : session.upload_progress=0)." 'INFO'
    Write-Log "Branches EOL (7.x / 8.0 / 8.1) : aucune version corrigée -> migration obligatoire ; l'atténuation n'est que temporaire." 'WARN'
    if (-not $MemoryUnlimited) {
        Write-Log "Atténuation 109618 désactivée (-NoMemoryUnlimited ou -RequestLimit vide) : relancer sans ces options pour l'activer." 'INFO'
    }
    ''                                                                 | Tee-Object -Append $log
    Get-WebApps

    # --- TABLEAU RÉCAPITULATIF (versions avant/après + patch + atténuation) ---
    ''                                                                 | Tee-Object -Append $log
    Write-Log "=== TABLEAU RÉCAPITULATIF (vert = corrigé/appliqué, rouge = à traiter) ===" 'INFO'
    $fmtH = '{0,-14} {1,-7} {2,-11} {3,-11} {4,-11} {5,-8} {6,-8} {7}'
    $hdr  = $fmtH -f 'INSTALLATION','BRANCHE','VERS.AVANT','VERS.APRES','PATCH','618:ATT','619:ATT','REMEDIATION'
    $dash = $fmtH -f ('-'*13),('-'*7),('-'*11),('-'*11),('-'*11),('-'*8),('-'*8),('-'*11)
    Write-Host $hdr ; Add-Content $log $hdr
    Write-Host $dash; Add-Content $log $dash
    foreach ($r in $recap) {
        # Console (coloré) : padding fait avant la couleur pour garder l'alignement.
        Write-Host ('{0,-14} {1,-7} {2,-11} {3,-11} ' -f $r.Inst,$r.Branche,$r.VA,$r.VP) -NoNewline
        Write-Host $r.Patch.PadRight(11) -ForegroundColor $r.PCol -NoNewline
        Write-Host ' ' -NoNewline
        Write-Host $r.A618.PadRight(8)   -ForegroundColor $r.C618 -NoNewline
        Write-Host ' ' -NoNewline
        Write-Host $r.A619.PadRight(8)   -ForegroundColor $r.C619 -NoNewline
        Write-Host ' ' -NoNewline
        Write-Host $r.Rem                -ForegroundColor $r.PCol
        # Journal (sans couleur)
        Add-Content $log ($fmtH -f $r.Inst,$r.Branche,$r.VA,$r.VP,$r.Patch,$r.A618,$r.A619,$r.Rem)
    }
    ''                                                                 | Tee-Object -Append $log
    Write-Log "PATCH = correctif de version (ferme les 2 CVE) ; 618:ATT = memory_limit=-1 ; 619:ATT = session.upload_progress=0." 'INFO'
}

# =========================================================================
# Déroulé
# =========================================================================
Write-Log "=== Étape 1 : durcissement ===" 'INFO'
Write-Log "Recherche EXHAUSTIVE des installations PHP (Plesk + IIS + PATH + XAMPP/WAMP/MAMP/Laragon + racines ciblées, tous lecteurs)..." 'INFO'
$installs = @(Get-PhpInstalls)
Write-Log "$($installs.Count) installation(s) PHP détectée(s)." 'INFO'
foreach ($i in $installs) { Write-Log ("  - {0}  [{1}]" -f $i.Php, $i.Label) 'INFO' }
if ($installs.Count -eq 0) {
    Write-Log "Aucune installation PHP détectée (stack non standard ? PHP embarqué dans une appli ?)." 'WARN'
}

# Instantané AVANT (version + upload_progress) pris AVANT toute modification
$before = Get-Snapshot $installs

foreach ($i in $installs) { Set-Hardening -Inst $i }

if (-not $HardenOnly) {
    if (-not $NoPlesk) { Update-PleskPhp }
    Restart-Web
}
# Note : les chemins restent stables (Plesk et stacks) -> on réutilise $installs
# pour comparer l'après au snapshot "avant".
Write-Report -installs $installs -before $before

Write-Log "Terminé. Détails dans $log" 'OK'
if ($DryRun) { Write-Log "C'était une simulation. Relancez sans -DryRun pour appliquer." 'WARN' }
