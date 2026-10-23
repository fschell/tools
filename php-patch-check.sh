#!/usr/bin/env bash
#
# php-patch-check.sh
# Prüft, ob die installierte PHP-Version gegen PHP2Shell
# (CVE-2026-109618 / CVE-2026-109619, CVSS 9.2) gepatcht ist.
#
# Gepatchte Mindestversionen je Branch:
#   8.5.x -> 8.5.12    8.4.x -> 8.4.27
#   8.3.x -> 8.3.36    8.2.x -> 8.2.35
#   7.4 - 8.1: kein offizielles Release (nur Source-Backports) -> als GEFÄHRDET behandeln
#
# Nur lesend. Ändert nichts am System. Auf dem zu prüfenden Server ausführen.
#
set -u

# --- gepatchte Mindest-Patchlevel je major.minor ---
declare -A MIN_PATCH=(
  ["8.5"]=12
  ["8.4"]=27
  ["8.3"]=36
  ["8.2"]=35
)

RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YEL=$'\033[0;33m'; BLD=$'\033[1m'; RST=$'\033[0m'
rc_global=0  # 0=alles ok, 1=verwundbar, 2=unklar

# Bewertet eine Versionsnummer "X.Y.Z" und gibt eine Zeile aus.
evaluate_version() {
  local label="$1" ver="$2"
  if [[ ! "$ver" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+) ]]; then
    printf "  %-22s %s(Version '%s' nicht lesbar)%s\n" "$label" "$YEL" "$ver" "$RST"
    (( rc_global < 2 )) && rc_global=2
    return
  fi
  local maj="${BASH_REMATCH[1]}" min="${BASH_REMATCH[2]}" patch="${BASH_REMATCH[3]}"
  local branch="${maj}.${min}"
  local required="${MIN_PATCH[$branch]:-}"

  if [[ -n "$required" ]]; then
    if (( patch >= required )); then
      printf "  %-22s %s%sGEPATCHT%s  (%s, benötigt >= %s.%s)\n" \
        "$label" "$GRN" "$BLD" "$RST" "$ver" "$branch" "$required"
    else
      printf "  %-22s %s%sVERWUNDBAR%s  (%s, benötigt >= %s.%s)\n" \
        "$label" "$RED" "$BLD" "$RST" "$ver" "$branch" "$required"
      rc_global=1
    fi
  else
    # Branch ohne offiziellen Fix (7.4-8.1) oder exotisch
    if (( maj < 8 || (maj == 8 && min <= 1) )); then
      printf "  %-22s %s%sVERWUNDBAR / EOL%s  (%s - kein offizielles Patch-Release, Branch isolieren/migrieren)\n" \
        "$label" "$RED" "$BLD" "$RST" "$ver"
      rc_global=1
    else
      printf "  %-22s %s(Branch %s unbekannt - manuell prüfen)%s\n" "$label" "$YEL" "$branch" "$RST"
      (( rc_global < 2 )) && rc_global=2
    fi
  fi
}

# Liest die PHP-Version aus einem Binary (z.B. php, php8.3, php-fpm).
version_from_binary() {
  "$1" -v 2>/dev/null | head -n1 | grep -oE 'PHP [0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}'
}

echo "${BLD}PHP-Patch-Check - PHP2Shell (CVE-2026-109618 / CVE-2026-109619)${RST}"
echo "Host: $(hostname 2>/dev/null) | Datum: $(date '+%Y-%m-%d %H:%M:%S')"
echo

# --- 1) Gefundene PHP-/PHP-FPM-Binaries im PATH und an üblichen Orten ---
echo "${BLD}1) Installierte PHP-Binaries${RST}"
declare -A seen=()
found_any=0
for name in php php-fpm php8.5 php8.4 php8.3 php8.2 php8.1 php8.0 php7.4 \
            php-fpm8.5 php-fpm8.4 php-fpm8.3 php-fpm8.2 php-fpm8.1; do
  while IFS= read -r bin; do
    [[ -z "$bin" ]] && continue
    real="$(readlink -f "$bin" 2>/dev/null || echo "$bin")"
    [[ -n "${seen[$real]:-}" ]] && continue
    seen[$real]=1
    ver="$(version_from_binary "$bin")"
    [[ -z "$ver" ]] && continue
    found_any=1
    evaluate_version "$bin" "$ver"
  done < <(command -v -a "$name" 2>/dev/null)
done
# zusätzlich typische FPM-Pfade, die nicht im PATH liegen
for bin in /usr/sbin/php-fpm* /opt/php*/bin/php /usr/local/php*/bin/php; do
  [[ -x "$bin" ]] || continue
  real="$(readlink -f "$bin" 2>/dev/null || echo "$bin")"
  [[ -n "${seen[$real]:-}" ]] && continue
  seen[$real]=1
  ver="$(version_from_binary "$bin")"
  [[ -z "$ver" ]] && continue
  found_any=1
  evaluate_version "$bin" "$ver"
done
(( found_any == 0 )) && { echo "  ${YEL}Kein PHP-Binary gefunden.${RST}"; (( rc_global < 2 )) && rc_global=2; }
echo

# --- 2) PHP-Version, die der Webserver tatsächlich ausliefert ---
# Oft weicht die CLI-Version von der FPM-/Modul-Version des Webservers ab!
echo "${BLD}2) Hinweis: Webserver-Version separat prüfen${RST}"
echo "  Die CLI-Version (oben) kann von der des Webservers abweichen."
echo "  Massgeblich für die Lücke ist die Version, die Apache/Nginx+FPM nutzt."
echo "  Zur Laufzeit-Prüfung z.B. temporär eine Datei anlegen und wieder löschen:"
echo "      echo '<?php echo PHP_VERSION;' > /pfad/zum/webroot/_v.php   # danach löschen!"
echo "  Oder (sicherer, ohne Web-Exposure):"
echo "      php-fpm -v    bzw.    systemctl status 'php*-fpm'"
echo

# --- Gesamtergebnis ---
echo "${BLD}Ergebnis${RST}"
case $rc_global in
  0) echo "  ${GRN}${BLD}OK${RST} - keine verwundbare PHP-Version unter den geprüften Binaries." ;;
  1) echo "  ${RED}${BLD}HANDLUNGSBEDARF${RST} - mindestens eine verwundbare PHP-Version gefunden. Umgehend aktualisieren." ;;
  2) echo "  ${YEL}${BLD}UNKLAR${RST} - Version(en) nicht eindeutig bestimmbar. Manuell prüfen." ;;
esac
echo
echo "Gepatchte Mindestversionen: 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35"
echo "7.4-8.1: kein offizielles Release -> isolieren oder migrieren."

exit $rc_global
