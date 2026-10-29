#!/usr/bin/env bash
#
# check-php2shell.sh — VÉRIFICATION SEULE (LECTURE SEULE : ne modifie rien).
#
# Rôle : dire s'il y a PHP ou non ; si oui, lister les versions présentes et
# indiquer si elles sont vulnérables à chacune des deux failles PHP2Shell :
#   • CVE-2026-109618 — Corruption mémoire lors de la gestion de l'OOM (RCE non authentifiée)
#   • CVE-2026-109619 — Use-after-free dans session.upload_progress (RCE + fuite mémoire)
# Puis donner la mesure corrective (exécuter le script de correction).
#
# Versions corrigées (ferment les DEUX CVE) : 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35.
# Branches EOL (8.1 / 8.0 / 7.x / 5.x) : aucun correctif officiel -> durcir + migrer.
#
# Usage :  ./check-php2shell.sh        (aucun privilège requis ; root conseillé
#                                        pour lire toutes les installations)
# Codes de sortie : 0 = PHP présent et tout corrigé ; 1 = au moins une install
#                   vulnérable ; 2 = aucune installation PHP détectée.
#
set -uo pipefail

FIX_SCRIPT="./fix-php2shell-v4.sh"
c_red=$'\e[31m'; c_grn=$'\e[32m'; c_yel=$'\e[33m'; c_blu=$'\e[36m'; c_rst=$'\e[0m'
say() { printf '%s\n' "$*"; }

# --- Découverte EXHAUSTIVE des binaires PHP (identique au correctif v4) -----
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
    local finder="find"; command -v timeout >/dev/null 2>&1 && finder="timeout 60 find"
    $finder /usr /usr/local /opt /srv -maxdepth 6 -type f \
      \( -name 'php' -o -name 'php[0-9]*' \) -perm -u+x 2>/dev/null || true
  } | while IFS= read -r p; do
        [ -n "$p" ] || continue
        rp="$(readlink -f "$p" 2>/dev/null || printf '%s' "$p")"
        [ -x "$rp" ] && printf '%s\n' "$rp"
      done | awk 'NF && !seen[$0]++' \
           | awk -F/ '$NF ~ /^php[0-9.]*$/'   # VRAI interpréteur uniquement
}
# ^ exclut php-fpm, php-cgi, php*-fpm-reopenlogs, etc. (évite faux positifs ET
#   d'exécuter par erreur un script utilitaire nommé « php... »).

php_ver() { "$1" -r 'echo PHP_VERSION;' 2>/dev/null || true; }
php_up()  { "$1" -r 'echo (int)ini_get("session.upload_progress.enabled");' 2>/dev/null || true; }
php_mem() { "$1" -r 'echo trim(ini_get("memory_limit"));' 2>/dev/null || true; }
fixed_for() {
  case "$1" in 8.5) echo 8.5.12;; 8.4) echo 8.4.27;; 8.3) echo 8.3.36;; 8.2) echo 8.2.35;; *) echo "";; esac
}
ver_ge() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$2" ]; }

# --- Autres technologies présentes (affiché si PHP absent) -----------------
have() { command -v "$1" >/dev/null 2>&1; }
show_tech() {  # $1 = libellé ; $2.. = commande de version
  local label="$1"; shift
  have "$1" || return 0
  local v; v="$("$@" 2>&1 | head -1 | tr -d '\r')"
  say "  • ${label} : ${v:-présent}"
}
detect_other_stacks() {
  say ""
  say "${c_blu}Autres technologies détectées sur le serveur :${c_rst}"
  local found=0
  { have node || have nodejs || have python3 || have python || have java || have dotnet \
    || have ruby || have go || have perl || have nginx || have apache2 || have httpd; } && found=1

  show_tech "Node.js"        node -v
  show_tech "Node.js"        nodejs --version
  show_tech "npm"            npm -v
  show_tech "Python 3"       python3 --version
  show_tech "Python 2"       python --version
  # Django (si le module est installé pour le python courant)
  if have python3 && python3 -c 'import django' >/dev/null 2>&1; then
    say "  • Django : $(python3 -c 'import django;print(django.get_version())' 2>/dev/null)"
  fi
  show_tech "Java"           java -version
  show_tech ".NET"           dotnet --version
  if have dotnet; then
    dotnet --list-runtimes 2>/dev/null | grep -i 'AspNetCore' | head -1 \
      | sed 's/^/  • ASP.NET Core : /' || true
  fi
  show_tech "Ruby"           ruby -v
  show_tech "Rails"          rails -v
  show_tech "Go"             go version
  have perl && say "  • Perl : $(perl -e 'printf "v%vd", $^V' 2>/dev/null)"
  show_tech "Serveur nginx"  nginx -v
  show_tech "Serveur Apache" apache2 -v
  show_tech "Serveur Apache" httpd -v

  [ "$found" = 1 ] || say "  (aucune technologie applicative courante détectée via la ligne de commande)"
}

# ---------------------------------------------------------------------------
say ""
say "${c_blu}=== Vérification PHP2Shell (CVE-2026-109618 / CVE-2026-109619) — LECTURE SEULE ===${c_rst}"
say "Aucune modification ne sera faite. Ce script ne fait que constater."
say ""

mapfile -t BINS < <(list_bins)

if [ "${#BINS[@]}" -eq 0 ]; then
  say "${c_grn}PHP : ABSENT.${c_rst} Aucun interpréteur PHP détecté sur ce serveur."
  say "-> Rien à corriger pour PHP2Shell (les CVE 109618/109619 ne concernent que PHP)."
  detect_other_stacks
  exit 2
fi

say "${c_blu}PHP : PRÉSENT${c_rst} — ${#BINS[@]} installation(s) détectée(s)."

vuln_count=0; ok_count=0

for bin in "${BINS[@]}"; do
  [ -n "$bin" ] || continue
  ver="$(php_ver "$bin")"; [ -n "$ver" ] || ver="?"
  mm="${ver%.*}"
  fixed="$(fixed_for "$mm")"
  up="$(php_up "$bin")"; mem="$(php_mem "$bin")"
  # « en place » en vert (mesure compensatoire présente), « ABSENTE » en rouge.
  att619=$([ "$up" = "0" ]    && echo "${c_grn}en place${c_rst}" || echo "${c_red}ABSENTE${c_rst}")
  att618=$([ "$mem" = "-1" ]  && echo "${c_grn}en place${c_rst}" || echo "${c_red}ABSENTE${c_rst}")

  # Verdict commun aux deux CVE (mêmes versions corrigées).
  if [ -n "$fixed" ]; then
    if [ "$ver" != "?" ] && ver_ge "$ver" "$fixed"; then
      state="CORRIGE"; verdict="${c_grn}NON vulnérable — corrigé (version >= $fixed)${c_rst}"
    else
      state="VULN"; verdict="${c_red}VULNÉRABLE — correctif disponible : mettre à jour vers $fixed${c_rst}"
    fi
  else
    state="EOL"; verdict="${c_red}VULNÉRABLE — branche en fin de vie, aucun correctif officiel${c_rst}"
  fi

  say ""
  say "────────────────────────────────────────────────────────────────────"
  say "Chemin   : $bin"
  say "Version  : $ver   (branche php$mm)"
  say "CVE-2026-109618 — Corruption mémoire (OOM) : $verdict"
  say "   atténuation memory_limit=-1 .............. $att618"
  say "CVE-2026-109619 — Use-after-free (upload_progress) : $verdict"
  say "   atténuation session.upload_progress=0 .... $att619"

  if [ "$state" = "CORRIGE" ]; then ok_count=$((ok_count+1)); else vuln_count=$((vuln_count+1)); fi
done

say ""
say "────────────────────────────────────────────────────────────────────"
say "${c_blu}BILAN${c_rst} : $ok_count corrigée(s), ${c_red}$vuln_count vulnérable(s)${c_rst} sur ${#BINS[@]}."
say ""

if [ "$vuln_count" -gt 0 ]; then
  say "${c_yel}MESURE CORRECTIVE${c_rst} :"
  say "  Veuillez exécuter le script de correction pour fixer la vulnérabilité :"
  say "      sudo $FIX_SCRIPT"
  say "  Il met à jour PHP vers la version corrigée (ferme les 2 CVE) et applique"
  say "  le durcissement. Pour les branches EOL, il durcit en attendant la migration"
  say "  (viser PHP 8.3 / 8.4), seule vraie solution."
  exit 1
fi

say "${c_grn}Toutes les installations PHP sont à une version corrigée. Rien à faire.${c_rst}"
say "(Contrôle complémentaire conseillé : que le durcissement reste en place.)"
exit 0
