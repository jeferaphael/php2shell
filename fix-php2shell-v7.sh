#!/usr/bin/env bash
#
# fix-php2shell.sh — Atténue et corrige PHP2Shell (CVE-2026-109618 / CVE-2026-109619)
# sur un serveur Debian, avec prise en charge des handlers PHP de Plesk.
#
# Démarche (identique à celle appliquée manuellement) :
#   1. DURCISSEMENT  : session.upload_progress.enabled = 0 sur toutes les install PHP
#                      (atténuation immédiate du vecteur connu) — avec sauvegardes.
#   2. PATCH DEBIAN  : apt upgrade des paquets php* -> versions corrigées.
#   3. PATCH PLESK   : plesk installer sur chaque handler PHP installé.
#   4. VERIFICATION  : rapport des versions + état du durcissement.
#
# Versions corrigées de référence : 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35
# Branches EOL (7.4, 8.0, 8.1) : pas de release upstream, seulement des backports
# éditeur -> le script NE PEUT PAS garantir le correctif par le n° de version et le
# signale explicitement. Le durcissement reste la protection dans ce cas.
#
# Usage :
#   sudo ./fix-php2shell-v7.sh     # fait TOUT automatiquement, sans aucune option
#
# Volet CVE-2026-109619 (use-after-free) : session.upload_progress.enabled = 0 (toujours).
# Volet CVE-2026-109618 (corruption OOM) : memory_limit = -1.
#   -> ACTIVÉ PAR DÉFAUT (désactivable via APPLY_MEMORY_UNLIMITED=0).
#      Les limites d'upload (upload_max_filesize / post_max_size) NE sont PAS modifiées
#      par défaut : l'existant est PRÉSERVÉ (aucun upload cassé). REQ_LIMIT=X impose
#      upload=X et post=+25 %. NB : memory_limit=-1 est une atténuation PLAUSIBLE mais
#      NON confirmée par l'éditeur -> « appliquée » ≠ « prouvée ».
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Paramètres / options
# ---------------------------------------------------------------------------
# Exécution automatique complète : aucune option (durcissement + patch + rapport).
DRY_RUN=0        # conservé en interne (toujours 0) : le script applique toujours
HARDEN_ONLY=0
DO_PLESK=1
TS="$(date +%Y%m%d-%H%M%S)"

# --- Volet CVE-2026-109618 (OOM) + hygiène — surchargeable par variable d'env. ---
#   Activé PAR DÉFAUT : un simple « ./fix-php2shell-v7.sh » applique les deux
#   atténuations (memory_limit=-1 + session.upload_progress=0).
#   PAR DÉFAUT, les limites d'upload (upload_max_filesize / post_max_size) NE SONT
#   PAS modifiées : le script PRÉSERVE les valeurs déjà en place (ne casse aucun
#   upload existant, aucune saisie nécessaire).
#   Pour IMPOSER un plafond : REQ_LIMIT=64M sudo ./fix-php2shell-v7.sh
#     -> upload_max_filesize = 64M et post_max_size = +25 % (80M).
#   Pour désactiver le volet 618 : APPLY_MEMORY_UNLIMITED=0 sudo ./fix-php2shell-v7.sh
APPLY_EXPOSE_PHP_OFF="${APPLY_EXPOSE_PHP_OFF:-1}"        # hygiène (sûr) : expose_php = Off
REQ_LIMIT="${REQ_LIMIT:-}"                              # vide = PRÉSERVE l'existant ; sinon impose upload=REQ_LIMIT, post=+25 %
APPLY_MEMORY_UNLIMITED="${APPLY_MEMORY_UNLIMITED:-1}"   # 109618 : memory_limit=-1 (par défaut ON)
APPLY_DISABLE_FUNCTIONS="${APPLY_DISABLE_FUNCTIONS:-0}" # réduit la surface (peut casser une appli) : opt-in
DISABLE_FUNCS="${DISABLE_FUNCS:-exec,passthru,shell_exec,system,proc_open,popen}"
LOG="/var/log/fix-php2shell-${TS}.log"
MARKER="CVE-2026-109618 / CVE-2026-109619 (PHP2Shell)"

# ---------------------------------------------------------------------------
# Utilitaires
# ---------------------------------------------------------------------------
c_red=$'\e[31m'; c_grn=$'\e[32m'; c_yel=$'\e[33m'; c_blu=$'\e[36m'; c_rst=$'\e[0m'
log()  { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$LOG" ; }
info() { log "${c_blu}[INFO]${c_rst} $*" ; }
ok()   { log "${c_grn}[ OK ]${c_rst} $*" ; }
warn() { log "${c_yel}[WARN]${c_rst} $*" ; }
err()  { log "${c_red}[ERR ]${c_rst} $*" ; }
run()  { # exécute, ou affiche seulement en dry-run
  if [ "$DRY_RUN" -eq 1 ]; then log "  (dry-run) $*"; else eval "$@" >>"$LOG" 2>&1; fi
}

[ "$(id -u)" -eq 0 ] || { err "À lancer en root (sudo)."; exit 1; }
info "Journal : $LOG"
[ "$DRY_RUN" -eq 1 ] && warn "MODE SIMULATION : aucune modification ne sera écrite."

# Politique limites d'upload : sans REQ_LIMIT, on PRÉSERVE les valeurs déjà en
# place (celles que l'admin a choisies font office de plafond de requête). On
# applique quand même memory_limit=-1 ; on informe juste que rien n'est plafonné
# en plus. Pour imposer/baisser un plafond explicite : fournir REQ_LIMIT.
if [ "$APPLY_MEMORY_UNLIMITED" = 1 ] && [ -z "$REQ_LIMIT" ]; then
  info "REQ_LIMIT non fourni : upload_max_filesize / post_max_size laissés INCHANGÉS (existant préservé)."
  info "memory_limit=-1 s'appuie alors sur les plafonds de requête déjà configurés. Forcer un plafond : REQ_LIMIT=32M."
fi

# ---------------------------------------------------------------------------
# 1) DURCISSEMENT — session.upload_progress.enabled = 0
# ---------------------------------------------------------------------------
# Désactive le suivi de progression d'upload en session (vecteur principal de
# PHP2Shell). Idempotent : ne modifie un fichier que s'il n'est pas déjà à 0.
# Construit le bloc de durcissement, entre marqueurs (ré-application idempotente).
# Sépare explicitement les deux CVE :
#   - 109619 (use-after-free) : session.upload_progress.enabled = 0   (toujours)
#   - 109618 (corruption OOM) : memory_limit=-1 + plafonds de requête (selon toggles)

# Calcule post_max_size à partir de REQ_LIMIT : +25 % (même unité), arrondi au
# supérieur, pour que post_max_size > upload_max_filesize (sinon un fichier à la
# taille max + les autres champs du formulaire dépassent post_max_size -> refus).
# Ex : 32M -> 40M, 64M -> 80M. Format inattendu -> valeur inchangée (repli sûr).
post_from_req() {  # $1 = ex "32M"
  local v="$1" num unit
  num="${v%[KkMmGg]}"            # partie numérique (retire un suffixe K/M/G final)
  unit="${v#"$num"}"            # suffixe restant (K/M/G) ou vide
  case "$num" in
    ''|*[!0-9]*) printf '%s' "$v"; return ;;   # pas un entier simple -> inchangé
  esac
  printf '%s%s' "$(( (num * 125 + 99) / 100 ))" "$unit"   # ceil(num * 1.25)
}

build_block() {
  printf '; >>> Durcissement PHP2Shell (CVE-2026-109618 / CVE-2026-109619) - %s >>>\n' "$TS"
  printf '; --- CVE-2026-109619 (use-after-free) : attenuation ---\n'
  printf 'session.upload_progress.enabled = 0\n'
  if [ "$APPLY_EXPOSE_PHP_OFF" = 1 ]; then
    printf '; --- Hygiene : ne pas divulguer la version de PHP ---\n'
    printf 'expose_php = Off\n'
  fi
  if [ -n "$REQ_LIMIT" ] || [ "$APPLY_MEMORY_UNLIMITED" = 1 ] || [ "$APPLY_DISABLE_FUNCTIONS" = 1 ]; then
    printf '; --- CVE-2026-109618 (corruption lors du OOM) : attenuation ---\n'
  fi
  if [ -n "$REQ_LIMIT" ]; then
    printf 'upload_max_filesize = %s\n' "$REQ_LIMIT"
    printf 'post_max_size = %s\n' "$(post_from_req "$REQ_LIMIT")"   # +25 % > upload
  fi
  [ "$APPLY_MEMORY_UNLIMITED" = 1 ] && printf 'memory_limit = -1\n'
  [ "$APPLY_DISABLE_FUNCTIONS" = 1 ] && printf 'disable_functions = %s\n' "$DISABLE_FUNCS"
  printf '; <<< Durcissement PHP2Shell <<<\n'
}

# Applique/rafraîchit le bloc dans un php.ini (remplace tout ancien bloc marqué).
# Le bloc est ajouté en fin de fichier -> ses directives priment (dernière valeur).
harden_ini() {  # $1 = chemin php.ini
  local ini="$1"
  [ -f "$ini" ] || return 0
  [ "$DRY_RUN" -eq 0 ] || { ok "(dry-run) durcirait : $ini"; return 0; }
  cp -a "$ini" "${ini}.bak-${TS}"
  sed -i '/; >>> Durcissement PHP2Shell/,/; <<< Durcissement PHP2Shell <<</d' "$ini"
  build_block >> "$ini"
  ok "durci : $ini (backup ${ini}.bak-${TS})"
}

# Applique le bloc via un drop-in conf.d (99-* chargé en dernier -> prioritaire).
harden_dropin() {  # $1 = dossier conf.d
  local dir="$1" file
  [ -d "$dir" ] || return 0
  file="$dir/99-cve-2026-109618-hardening.ini"
  [ "$DRY_RUN" -eq 0 ] || { ok "(dry-run) durcirait : $file"; return 0; }
  build_block > "$file"
  ok "durci (drop-in) : $file"
}

# Durcit un binaire PHP en s'appuyant sur SA propre configuration, quelle que
# soit la distribution (RHEL/CentOS /etc/php.ini + /etc/php.d, autonome, etc.).
# On demande à PHP où sont ses fichiers via `php --ini`.
harden_bin() {  # $1 = chemin du binaire php
  local bin="$1" ini scandir
  [ -x "$bin" ] || return 0
  # NB : « || true » indispensable — un binaire non-CLI (SAPI CGI p.ex.) sort en
  # code non-zéro sur « --ini » et, avec set -e + pipefail, tuerait tout le script.
  ini="$("$bin" --ini 2>/dev/null | sed -n 's/^Loaded Configuration File:[[:space:]]*//p' | head -1 || true)"
  scandir="$("$bin" --ini 2>/dev/null | sed -n 's/^Scan for additional .ini files in:[[:space:]]*//p' | head -1 || true)"
  if [ -n "$scandir" ] && [ -d "$scandir" ]; then
    harden_dropin "$scandir"                       # méthode propre : drop-in 99-*
  elif [ -n "$ini" ] && [ "$ini" != "(none)" ] && [ -f "$ini" ]; then
    harden_ini "$ini"                              # pas de dossier de scan : on édite l'ini
  else
    warn "aucun php.ini exploitable pour $bin (ni dossier de scan ni ini chargé)"
  fi
}

# ---------------------------------------------------------------------------
# Helpers d'inventaire + instantané AVANT (version + upload_progress)
# ---------------------------------------------------------------------------
# Liste TOUS les binaires PHP présents, quel que soit le mode d'installation :
# Plesk, Debian/sury, RHEL/Remi, cPanel EA, compilé /usr/local, PATH, alternatives,
# + recherche bornée sur les racines courantes. Dédoublonné par chemin réel.
list_bins() {
  {
    local b
    for b in \
      /opt/plesk/php/*/bin/php \
      /usr/bin/php /usr/bin/php[0-9]* \
      /usr/local/bin/php /usr/local/bin/php[0-9]* \
      /usr/local/php*/bin/php \
      /opt/php*/bin/php /opt/php/*/bin/php \
      /opt/remi/php*/root/usr/bin/php \
      /opt/cpanel/ea-php*/root/usr/bin/php ; do
      [ -x "$b" ] && printf '%s\n' "$b"
    done
    command -v php 2>/dev/null || true
    update-alternatives --list php 2>/dev/null || true
    # Recherche bornée (bornée en profondeur + délai) pour les installs exotiques.
    local finder="find"; command -v timeout >/dev/null 2>&1 && finder="timeout 60 find"
    $finder /usr /usr/local /opt /srv -maxdepth 6 -type f \
      \( -name 'php' -o -name 'php[0-9]*' \) -perm -u+x 2>/dev/null || true
  } | while IFS= read -r p; do
        [ -n "$p" ] || continue
        rp="$(readlink -f "$p" 2>/dev/null || printf '%s' "$p")"
        [ -x "$rp" ] && printf '%s\n' "$rp"
      done | awk 'NF && !seen[$0]++' \
           | awk -F/ '$NF ~ /^php[0-9.]*$/' \
           | grep -Ev '/cgi-bin/'   # VRAI interpréteur CLI uniquement : exclut php-fpm,
}                                    # php-cgi, php*-fpm-reopenlogs ET /usr/lib/cgi-bin/phpX.Y
# Version : on n'accepte qu'un vrai triplet x.y.z (un binaire non-CLI recracherait
# son aide sur « -r » -> aucun triplet -> version vide, pas de pavé parasite).
php_ver() { "$1" -r 'echo PHP_VERSION;' 2>/dev/null | grep -Eom1 '[0-9]+\.[0-9]+\.[0-9]+' || true; }
php_up()  { "$1" -r 'echo (int)ini_get("session.upload_progress.enabled");' 2>/dev/null || true; }
php_mem() { "$1" -r 'echo trim(ini_get("memory_limit"));' 2>/dev/null || true; }
fmt_up()  { case "$1" in 0) echo "0 (Off)";; 1) echo "1 (On)";; *) echo "?";; esac; }

# Instantané AVANT (version + upload_progress), pris AVANT toute modification.
declare -A BEFORE_VER BEFORE_UP
while IFS= read -r _b; do
  [ -n "$_b" ] || continue
  BEFORE_VER["$_b"]="$(php_ver "$_b")"
  BEFORE_UP["$_b"]="$(php_up "$_b")"
done < <(list_bins)

info "=== Étape 1 : durcissement ==="
# PHP Debian / deb.sury.org : /etc/php/<ver>/<sapi>/ (couvre aussi le FPM)
if [ -d /etc/php ]; then
  for sapi_dir in /etc/php/*/*/conf.d; do
    [ -d "$sapi_dir" ] && harden_dropin "$sapi_dir"
  done
fi
# PHP Plesk : /opt/plesk/php/<ver>/etc/php.ini (pas de dossier de scan -> on édite l'ini)
if [ -d /opt/plesk/php ]; then
  for ini in /opt/plesk/php/*/etc/php.ini; do harden_ini "$ini"; done
fi
# Générique : chaque binaire PHP détecté est durci via SA propre config
# (indispensable sur RHEL/CentOS, PHP autonome ou compilé — layouts non Debian).
while IFS= read -r _b; do
  [ -n "$_b" ] && harden_bin "$_b"
done < <(list_bins)

# ---------------------------------------------------------------------------
# 2) PATCH DEBIAN (apt)
# ---------------------------------------------------------------------------
patch_debian() {
  command -v apt-get >/dev/null || { warn "apt-get absent, étape Debian ignorée."; return 0; }
  info "=== Étape 2 : patch des paquets PHP Debian ==="
  run "apt-get update"
  local pkgs
  pkgs="$(dpkg -l 2>/dev/null | awk '/^ii/ && $2 ~ /^php[0-9]/ {print $2}' | tr '\n' ' ')"
  if [ -z "${pkgs// }" ]; then info "Aucun paquet php* Debian installé."; return 0; fi
  info "Paquets concernés : $pkgs"
  if [ "$DRY_RUN" -eq 1 ]; then
    apt-get install --only-upgrade -s $pkgs 2>/dev/null | grep -E '^Inst ' | tee -a "$LOG" || true
  else
    DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y $pkgs >>"$LOG" 2>&1 || {
      err "Échec apt upgrade (voir $LOG)"; return 1; }
  fi
  ok "Patch Debian terminé (redémarrage des services en fin d'exécution)."
}

# ---------------------------------------------------------------------------
# Redémarrage COMPLET des workers (restart, pas reload) — requis pour 109619 :
# un reload ne recycle pas forcément les workers forkés du master.
# Couvre FPM (Debian/Plesk/générique) + Apache mod_php (apache2/httpd).
# ---------------------------------------------------------------------------
# Redémarre UN service via le gestionnaire présent, dans l'ordre : systemd,
# puis OpenRC (Alpine/Gentoo), puis SysV/init.d. Silencieux si le service est
# absent ou inactif. Rend le redémarrage indépendant de systemd.
svc_restart() {  # $1 = nom du service
  local s="$1"
  if command -v systemctl >/dev/null 2>&1 && systemctl list-units >/dev/null 2>&1; then
    systemctl is-active --quiet "$s" 2>/dev/null && { run "systemctl restart $s" && ok "redémarré : $s"; }
    return 0
  fi
  if command -v rc-service >/dev/null 2>&1 && rc-service --exists "$s" 2>/dev/null; then
    run "rc-service $s restart" && ok "redémarré (OpenRC) : $s"; return 0
  fi
  if [ -x "/etc/init.d/$s" ]; then
    if command -v service >/dev/null 2>&1; then run "service $s restart" && ok "redémarré (SysV) : $s"
    else run "/etc/init.d/$s restart" && ok "redémarré (init.d) : $s"; fi
    return 0
  fi
  return 0
}

restart_web() {
  info "=== Redémarrage complet des workers PHP + serveur web ==="
  local svc has_systemd=0
  command -v systemctl >/dev/null 2>&1 && systemctl list-units >/dev/null 2>&1 && has_systemd=1

  if [ "$has_systemd" = 1 ]; then
    # Énumération via systemd (Debian/RHEL/SUSE/Plesk).
    while IFS= read -r svc; do
      [ -n "$svc" ] && svc_restart "$svc"
    done < <(systemctl list-units --type=service 2>/dev/null \
              | grep -Eo '(php[0-9.]*-fpm|plesk-php[0-9]+-fpm)\.service' | sort -u)
  else
    # Repli sans systemd : on cherche les services FPM dans init.d et OpenRC
    # (Alpine : « php-fpm82 », certains : « php82-fpm »…).
    warn "systemd absent : repli OpenRC / SysV / init.d pour le redémarrage."
    while IFS= read -r svc; do
      [ -n "$svc" ] && svc_restart "$svc"
    done < <({ ls /etc/init.d 2>/dev/null; \
               command -v rc-update >/dev/null 2>&1 && rc-update show 2>/dev/null | awk '{print $1}'; } \
             | grep -Ei 'fpm' | sort -u)
  fi
  # Serveur web (mod_php) — noms communs selon l'OS.
  for svc in apache2 httpd nginx; do svc_restart "$svc"; done
}

# ---------------------------------------------------------------------------
# 3) PATCH PLESK (plesk installer, par composant installé)
# ---------------------------------------------------------------------------
patch_plesk() {
  command -v plesk >/dev/null || { info "Plesk non détecté, étape ignorée."; return 0; }
  info "=== Étape 3 : patch des handlers PHP Plesk ==="
  local comp ver svc
  for dir in /opt/plesk/php/*/; do
    [ -x "${dir}bin/php" ] || continue
    ver="$(basename "$dir")"                 # ex: 8.4
    comp="php${ver}"                         # nom du composant Plesk
    info "Mise à jour composant Plesk : $comp"
    if [ "$DRY_RUN" -eq 1 ]; then
      log "  (dry-run) plesk installer --select-release-current --install-component $comp"
    else
      plesk installer --select-release-current --install-component "$comp" >>"$LOG" 2>&1 || {
        warn "Échec/instable sur $comp (voir $LOG)"; continue; }
    fi
    # systemd peut avoir changé + redémarrage du fpm du handler
    svc="plesk-php${ver//./}-fpm"            # ex: plesk-php84-fpm
    run "systemctl daemon-reload"
    if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}"; then
      run "systemctl restart $svc" && ok "redémarré : $svc"
    fi
  done
  ok "Patch Plesk terminé."
}

# ---------------------------------------------------------------------------
# 2bis) PATCH RHEL / CentOS / AlmaLinux / Rocky (dnf/yum) et SUSE (zypper)
# ---------------------------------------------------------------------------
patch_rpm() {
  local mgr=""
  command -v dnf    >/dev/null 2>&1 && mgr="dnf"
  [ -z "$mgr" ] && command -v yum    >/dev/null 2>&1 && mgr="yum"
  [ -z "$mgr" ] && command -v zypper >/dev/null 2>&1 && mgr="zypper"
  [ -n "$mgr" ] || { info "Ni dnf/yum ni zypper : étape RPM/SUSE ignorée."; return 0; }
  info "=== Étape 2bis : patch des paquets PHP via $mgr ==="
  local pkgs
  pkgs="$(rpm -qa --qf '%{NAME}\n' 2>/dev/null | grep -E '^php([0-9]+)?(-|$)' | sort -u | tr '\n' ' ')"
  if [ -z "${pkgs// }" ]; then info "Aucun paquet php* (rpm) installé."; return 0; fi
  info "Paquets concernés : $pkgs"
  if [ "$mgr" = "zypper" ]; then
    run "zypper --non-interactive update $pkgs"
  else
    run "$mgr -y update $pkgs"
  fi
  ok "Patch $mgr terminé (redémarrage des services en fin d'exécution)."
}

# ---------------------------------------------------------------------------
# 2quater) PATCH Alpine Linux (apk) — conteneurs / musl
# ---------------------------------------------------------------------------
# Alpine nomme ses paquets phpXY (ex. php82, php82-fpm, php82-cli). On met à jour
# uniquement les paquets php* installés. Le « [0-9] » après php évite d'attraper
# des paquets comme « phpmyadmin ».
patch_apk() {
  command -v apk >/dev/null 2>&1 || return 0
  info "=== Étape 2quater : patch des paquets PHP via apk (Alpine) ==="
  local pkgs
  pkgs="$(apk info 2>/dev/null | grep -E '^php[0-9]' | sort -u | tr '\n' ' ')"
  if [ -z "${pkgs// }" ]; then info "Aucun paquet php[0-9]* (apk) installé."; return 0; fi
  info "Paquets concernés : $pkgs"
  run "apk update"
  run "apk add --upgrade $pkgs"   # met à jour les paquets nommés vers la dernière version du dépôt
  ok "Patch apk terminé (redémarrage des services en fin d'exécution)."
}

# ---------------------------------------------------------------------------
# 2ter) PATCH PHP CloudLinux (alt-php) — hors périmètre de patch_rpm
# ---------------------------------------------------------------------------
# CloudLinux installe son PHP sous des paquets nommés « alt-php* » (sélecteur
# PHP Selector : alt-php74/80/82/83..., plus alt-php-internal utilisé en interne).
# Ces noms NE matchent PAS le filtre « ^php... » de patch_rpm, et ce ne sont pas
# des handlers Plesk : ils ne seraient donc jamais mis à jour sans cette étape.
patch_altphp() {
  local pkgs=""
  # --- Monde RPM (CloudLinux « classique », base RHEL) -----------------------
  if command -v rpm >/dev/null 2>&1; then
    local mgr=""
    command -v dnf >/dev/null 2>&1 && mgr="dnf"
    [ -z "$mgr" ] && command -v yum >/dev/null 2>&1 && mgr="yum"
    if [ -n "$mgr" ]; then
      pkgs="$(rpm -qa --qf '%{NAME}\n' 2>/dev/null | grep -E '^alt-php' | sort -u | tr '\n' ' ')"
      if [ -n "${pkgs// }" ]; then
        info "=== Étape 2ter : patch du PHP CloudLinux (alt-php) via $mgr ==="
        info "Paquets alt-php présents : $pkgs"
        # Glob idiomatique CloudLinux (yum/dnf développent eux-mêmes « alt-php* »).
        run "$mgr -y update 'alt-php*'"
        ok "Patch CloudLinux alt-php (rpm) terminé."
        return 0
      fi
    fi
  fi
  # --- Monde Debian/Ubuntu (.deb : CloudLinux/Imunify sur base Debian) -------
  # patch_debian ne les voit pas (noms « alt-php* », pas « php[0-9] »).
  if command -v dpkg >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
    pkgs="$(dpkg -l 2>/dev/null | awk '/^ii/ && $2 ~ /^alt-php/ {print $2}' | sort -u | tr '\n' ' ')"
    if [ -n "${pkgs// }" ]; then
      info "=== Étape 2ter : patch du PHP CloudLinux (alt-php) via apt ==="
      info "Paquets alt-php présents : $pkgs"
      run "apt-get update"
      if [ "$DRY_RUN" -eq 1 ]; then
        apt-get install --only-upgrade -s $pkgs 2>/dev/null | grep -E '^Inst ' | tee -a "$LOG" || true
      else
        DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y $pkgs >>"$LOG" 2>&1 || {
          warn "Échec apt sur alt-php (voir $LOG)"; return 1; }
      fi
      ok "Patch CloudLinux alt-php (apt) terminé."
      return 0
    fi
  fi
  info "Aucun paquet alt-php* (CloudLinux) installé."
}

# ---------------------------------------------------------------------------
# 4) VERIFICATION / RAPPORT
# ---------------------------------------------------------------------------
# Versions corrigées connues par branche (pour les branches supportées).
fixed_for() {  # $1 = version majeure.mineure -> version corrigée attendue, ou "" si EOL
  case "$1" in
    8.5) echo "8.5.12" ;; 8.4) echo "8.4.27" ;; 8.3) echo "8.3.36" ;; 8.2) echo "8.2.35" ;;
    *)   echo "" ;;   # 8.1/8.0/7.4/... -> EOL, pas de n° de référence fiable
  esac
}
ver_ge() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$2" ]; }

# Domaines (applications) rattachés à une version de PHP.
# La table `domains` contient les domaines principaux ET les sous-domaines (chacun
# avec sa propre ligne `hosting.php_handler_id`), donc la jointure les couvre tous.
# Les alias www.* sont de simples ServerAlias Apache (pas de ligne en base) : ils
# partagent le handler du domaine parent, déjà listé -> inutile de les dédoubler.
# Formes de php_handler_id :
#   - PHP fourni par Plesk : plesk-phpXY-{fpm,fastcgi,cgi}
#   - PHP système (OS)     : fpm | fastcgi | cgi | module  (SANS n° de version)
plesk_db() { plesk db -Ne "$1" 2>/dev/null; }

# Domaines/sous-domaines servis par le PHP *fourni par Plesk* d'une version donnée.
plesk_apps_for() {  # $1 = "8.2" -> un nom par ligne (vide si aucun / pas Plesk)
  command -v plesk >/dev/null 2>&1 || return 0
  local xy="${1/./}"
  plesk_db "SELECT d.name FROM domains d JOIN hosting h ON h.dom_id=d.id \
              WHERE h.php_handler_id LIKE 'plesk-php${xy}-%' ORDER BY d.name;"
}

# Domaines/sous-domaines servis par le PHP *système* (handler sans version).
plesk_apps_system() {
  command -v plesk >/dev/null 2>&1 || return 0
  plesk_db "SELECT d.name FROM domains d JOIN hosting h ON h.dom_id=d.id \
              WHERE h.php_handler_id IS NOT NULL AND h.php_handler_id <> '' \
                AND h.php_handler_id NOT LIKE 'plesk-php%' ORDER BY d.name;"
}

# Nom des pools PHP-FPM liés à une version (hors Plesk). Format .conf standard :
# une section [nom_du_pool] par application/site. C'est le signal le plus fiable,
# cross-distro, pour « quelle application tourne sur quel PHP ».
pools_for_version() {  # $1 = "8.2"
  local xy="$1" nn="${1/./}" d conf
  for d in /etc/php/"$xy"/fpm/pool.d /usr/local/etc/php-fpm.d \
           /opt/remi/php"$nn"/root/etc/php-fpm.d; do
    [ -d "$d" ] || continue
    for conf in "$d"/*.conf; do
      [ -f "$conf" ] && sed -n 's/^[[:space:]]*\[\(.*\)\][[:space:]]*$/pool:\1/p' "$conf"
    done
  done
}
# Pools du PHP système RHEL/CentOS (dossier unique, sans version dans le chemin).
pools_system() {
  local d conf
  for d in /etc/php-fpm.d; do
    [ -d "$d" ] || continue
    for conf in "$d"/*.conf; do
      [ -f "$conf" ] && sed -n 's/^[[:space:]]*\[\(.*\)\][[:space:]]*$/pool:\1/p' "$conf"
    done
  done
}

# Inventaire best-effort des applications web (serveur web -> racine + nom de site),
# tous stacks confondus. Purement informatif (le mapping exact vers une version PHP
# dépend trop de la config pour être garanti) ; affiché après le tableau.
discover_web_apps() {
  info "=== Applications web détectées (best-effort : serveur web -> racine) ==="
  local f any=0
  # Apache (Debian, RHEL, Plesk)
  for f in /etc/apache2/sites-enabled/*.conf /etc/apache2/sites-enabled/* \
           /etc/httpd/conf.d/*.conf /etc/httpd/conf/httpd.conf \
           /var/www/vhosts/system/*/conf/*.conf; do
    [ -f "$f" ] || continue
    awk 'BEGIN{sn=""}
         {k=tolower($1)}
         k=="servername"{sn=$2}
         k=="documentroot"{gsub(/"/,"",$2); print "  [apache] "$2"   <= "sn}' "$f" 2>/dev/null \
      && any=1
  done
  # nginx
  for f in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf; do
    [ -f "$f" ] || continue
    awk 'BEGIN{sn=""}
         {k=tolower($1)}
         k=="server_name"{sn=$2; gsub(/;/,"",sn)}
         k=="root"{r=$2; gsub(/;/,"",r); print "  [nginx]  "r"   <= "sn}' "$f" 2>/dev/null \
      && any=1
  done
  [ "$any" = 1 ] || info "  (aucun vhost Apache/nginx lisible — stack non standard, Plesk DB, ou conteneur)"
}

report() {
  info "=== Résumé détaillé par installation PHP (patch + atténuation, par CVE) ==="
  # Binaire système représentatif : reçoit domaines/pools système une seule fois.
  local a sysrep=""
  while IFS= read -r a; do
    case "$a" in /opt/plesk/php/*) ;; *) [ -z "$sysrep" ] && sysrep="$a" ;; esac
  done < <(list_bins)

  local bin cur mm fixv fixnum corr va ua mem m618 up m619 kind applist lbl st rem count=0
  local rfmt='%-15s %-8s %-12s %-12s %-11s %-11s %s'
  local -a RECAP=()
  while IFS= read -r bin; do
    [ -n "$bin" ] || continue
    count=$((count+1))
    cur="$(php_ver "$bin")"; [ -n "$cur" ] || cur="?"
    mm="${cur%.*}"
    va="${BEFORE_VER[$bin]:-}"; [ -n "$va" ] || va="(non relevé)"
    ua="$cur"
    # PATCH (identique aux deux CVE : mêmes versions corrigées).
    fixnum="$(fixed_for "$mm")"      # version corrigée numérique (ou vide si EOL)
    fixv="$fixnum"
    if [ -n "$fixv" ]; then
      if ver_ge "$cur" "$fixv"; then corr="OK — corrigé (version >= $fixv)"
      else corr="NON — à mettre à jour vers $fixv"; fi
    else
      corr="EOL? — branche en fin de vie, aucune version corrigée (migration requise)"
      fixv="aucune (branche EOL — viser 8.3 / 8.4)"
    fi
    # ATTÉNUATIONS (état APRÈS, lu dans la config effective du binaire).
    mem="$(php_mem "$bin")"; [ "$mem" = "-1" ] && m618="Oui — appliquée" || m618="Non — non appliquée (opt-in)"
    up="$(php_up "$bin")";   [ "$up"  = "0"  ] && m619="Oui — appliquée"  || m619="Non — non appliquée"

    # Applications / éléments liés à cette installation.
    local -a apps=()
    case "$bin" in
      /opt/plesk/php/*/bin/php)
        kind="Handler Plesk (sites web)"
        while IFS= read -r a; do [ -n "$a" ] && apps+=("$a"); done < <(plesk_apps_for "$mm")
        ;;
      *)
        kind="PHP système / FPM / CLI"
        if [ "$bin" = "$sysrep" ]; then
          while IFS= read -r a; do [ -n "$a" ] && apps+=("$a"); done < <(plesk_apps_system)
          while IFS= read -r a; do [ -n "$a" ] && apps+=("$a"); done < <(pools_system)
        fi
        while IFS= read -r a; do [ -n "$a" ] && apps+=("$a"); done < <(pools_for_version "$mm")
        ;;
    esac
    if [ "${#apps[@]}" -eq 0 ]; then
      applist="(aucune application liée détectée — interpréteur système / CLI)"
    else
      applist="$(printf '%s, ' "${apps[@]}")"; applist="${applist%, }"
    fi

    # Couleurs : vert si corrigé/appliqué, rouge sinon.
    local cc m618c m619c
    case "$corr"  in OK*)  cc="$c_grn"   ;; *) cc="$c_red"   ;; esac
    case "$m618"  in Oui*) m618c="$c_grn";; *) m618c="$c_red";; esac
    case "$m619"  in Oui*) m619c="$c_grn";; *) m619c="$c_red";; esac

    # Étiquette courte + état + remédiation pour le tableau récapitulatif.
    case "$bin" in
      /opt/plesk/php/*/bin/php) lbl="plesk $mm" ;;
      */alt/php-internal/*)     lbl="alt-php $mm" ;;
      /usr/bin/php*)            lbl="systeme $mm" ;;
      *)                        lbl="autre $mm" ;;
    esac
    case "$corr" in
      OK*)  st="Corrige"    ; rem="Aucune (a jour)" ;;
      NON*) st="Vulnerable" ; rem="Mettre a jour -> $fixnum" ;;
      *)    st="Vuln.(EOL)" ; rem="Migrer 8.3/8.4 (durcir)" ;;
    esac
    # Tableau final : PATCH (commun aux 2 CVE) + ATTÉNUATION séparée par CVE.
    local mit618 mit619 _row
    case "$m618" in Oui*) mit618="Oui";; *) mit618="Non";; esac
    case "$m619" in Oui*) mit619="Oui";; *) mit619="Non";; esac
    local pPatch="${cc}$(printf '%-11s' "$st")${c_rst}"
    local pA618="${m618c}$(printf '%-8s' "$mit618")${c_rst}"
    local pA619="${m619c}$(printf '%-8s' "$mit619")${c_rst}"
    local pRem="${cc}${rem}${c_rst}"
    printf -v _row '%-13s %-7s %-11s %-11s %s %s %s %s' \
           "$lbl" "php$mm" "$va" "$ua" "$pPatch" "$pA618" "$pA619" "$pRem"
    RECAP+=("$_row")

    {
      printf '\n────────────────────────────────────────────────────────────────────\n'
      printf 'Chemin du PHP détecté : %s\n' "$bin"
      printf 'Branche               : php%s\n' "$mm"
      printf 'Version AVANT upgrade  : %s\n' "$va"
      printf 'Version APRÈS upgrade  : %s\n' "$ua"
      printf 'Type / rattachement    : %s\n' "$kind"
      printf 'Applications détectées : %s\n' "$applist"
      printf '\n'
      printf "CVE-2026-109618 — Corruption mémoire lors de la gestion de l'OOM (RCE non authentifiée)\n"
      printf '   • Patch       : Mise à jour de PHP vers la version corrigée (%s)\n' "$fixv"
      printf '                   -> %b%s%b\n' "$cc" "$corr" "$c_rst"
      printf '   • Atténuation : memory_limit = -1 (+ post_max_size / upload_max_filesize)\n'
      printf '                   -> %b%s%b\n' "$m618c" "$m618" "$c_rst"
      printf 'CVE-2026-109619 — Use-after-free dans session.upload_progress (RCE + fuite mémoire)\n'
      printf '   • Patch       : Mise à jour de PHP vers la version corrigée (%s)\n' "$fixv"
      printf '                   -> %b%s%b\n' "$cc" "$corr" "$c_rst"
      printf '   • Atténuation : session.upload_progress.enabled = 0\n'
      printf '                   -> %b%s%b\n' "$m619c" "$m619" "$c_rst"
    } | tee -a "$LOG"
  done < <(list_bins)

  printf '\n' | tee -a "$LOG"
  info "Installations PHP détectées : $count."
  info "PATCH = seule mesure qui FERME réellement les deux failles (mise à jour de version)."
  info "ATTÉNUATION = réduit le risque sans corriger (109618 : memory_limit=-1 ; 109619 : session.upload_progress=0)."
  warn "Branches EOL (7.x / 8.0 / 8.1) : aucune version corrigée -> migration obligatoire, l'atténuation n'est que temporaire."
  [ "$APPLY_MEMORY_UNLIMITED" = 1 ] || info "Atténuation 109618 en opt-in : relancer avec 'APPLY_MEMORY_UNLIMITED=1 REQ_LIMIT=32M' pour l'activer."
  printf '\n' | tee -a "$LOG"
  discover_web_apps

  # --- TABLEAU RÉCAPITULATIF (essentiel : versions avant/après + patch + atténuation) ---
  printf '\n' | tee -a "$LOG"
  info "=== TABLEAU RÉCAPITULATIF  (vert = corrigé / appliqué, rouge = à traiter) ==="
  local hfmt='%-13s %-7s %-11s %-11s %-11s %-8s %-8s %s\n'
  printf "$hfmt" "INSTALLATION" "BRANCHE" "VERS.AVANT" "VERS.APRES" "PATCH" "618:ATT" "619:ATT" "REMEDIATION" | tee -a "$LOG"
  printf "$hfmt" "-------------" "-------" "-----------" "-----------" "-----------" "--------" "--------" "-----------" | tee -a "$LOG"
  local r
  for r in "${RECAP[@]}"; do printf '%s\n' "$r" | tee -a "$LOG"; done
  printf '\n' | tee -a "$LOG"
  info "PATCH = correctif de version (ferme les 2 CVE) ; 618:ATT = memory_limit=-1 ; 619:ATT = session.upload_progress=0."
}

# ---------------------------------------------------------------------------
# Déroulé
# ---------------------------------------------------------------------------
if [ "$HARDEN_ONLY" -eq 0 ]; then
  patch_debian || warn "Étape Debian en échec partiel."
  patch_rpm    || warn "Étape RPM/SUSE en échec partiel."
  patch_apk    || warn "Étape Alpine (apk) en échec partiel."
  patch_altphp || warn "Étape CloudLinux alt-php en échec partiel."
  [ "$DO_PLESK" -eq 1 ] && { patch_plesk || warn "Étape Plesk en échec partiel."; }
fi
# Redémarrage complet garanti, même si une étape de patch a échoué (prise en
# compte du durcissement + recyclage des workers pour la 109619).
restart_web || true
report

ok "Terminé. Détails dans $LOG"
exit 0
