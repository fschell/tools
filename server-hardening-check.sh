#!/usr/bin/env bash
#
# server-hardening-check.sh
# Lesendes Audit gängiger Härtungs-Einstellungen eines Linux-Servers.
# Veraendert NICHTS am System - gibt nur Befunde + Empfehlungen aus.
#
# Exit-Codes:  0 = keine FAILs  ·  1 = mind. ein FAIL  ·  (WARN allein -> 0)
#
# Hinweis: Fuer vollstaendige Ergebnisse als root/sudo ausfuehren.
#
set -u

RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YEL=$'\033[0;33m'; BLU=$'\033[0;34m'; BLD=$'\033[1m'; RST=$'\033[0m'
pass=0; warn=0; fail=0

sec()  { printf "\n%s%s%s\n" "$BLD" "$1" "$RST"; }
PASS() { printf "  %s[PASS]%s %s\n" "$GRN" "$RST" "$1"; pass=$((pass+1)); }
WARN() { printf "  %s[WARN]%s %s\n" "$YEL" "$RST" "$1"; warn=$((warn+1)); }
FAIL() { printf "  %s[FAIL]%s %s\n" "$RED" "$RST" "$1"; fail=$((fail+1)); }
INFO() { printf "  %s[info]%s %s\n" "$BLU" "$RST" "$1"; }

# effektiven sshd-Wert auslesen (bevorzugt 'sshd -T', sonst Config-Grep)
sshd_val() {
  local key="$1" out
  if command -v sshd >/dev/null 2>&1 && out="$(sshd -T 2>/dev/null)"; then
    echo "$out" | awk -v k="${key,,}" 'tolower($1)==k{print $2; found=1} END{exit !found}' && return 0
  fi
  grep -iE "^[[:space:]]*${key}[[:space:]]" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null \
    | tail -n1 | awk '{print $2}'
}

echo "${BLD}Server-Hardening-Check${RST}"
echo "Host: $(hostname 2>/dev/null) | Datum: $(date '+%Y-%m-%d %H:%M:%S') | User: $(id -un) (uid=$(id -u))"
[[ $(id -u) -ne 0 ]] && INFO "Nicht als root - einige Pruefungen evtl. unvollstaendig."

# --- 1) SSH ---
sec "1) SSH-Konfiguration"
if command -v sshd >/dev/null 2>&1 || [[ -f /etc/ssh/sshd_config ]]; then
  v="$(sshd_val permitrootlogin)"
  case "${v,,}" in
    no|prohibit-password|without-password) PASS "PermitRootLogin = ${v:-?}" ;;
    "") WARN "PermitRootLogin nicht bestimmbar (Default je nach Distro 'prohibit-password')" ;;
    *) FAIL "PermitRootLogin = $v  -> auf 'no' oder 'prohibit-password' setzen" ;;
  esac
  v="$(sshd_val passwordauthentication)"
  case "${v,,}" in
    no) PASS "PasswordAuthentication = no (nur Keys)" ;;
    yes) WARN "PasswordAuthentication = yes  -> wenn moeglich auf 'no' (SSH-Keys) umstellen" ;;
    *) WARN "PasswordAuthentication nicht bestimmbar" ;;
  esac
  v="$(sshd_val permitemptypasswords)"
  [[ "${v,,}" == no || -z "$v" ]] && PASS "PermitEmptyPasswords = ${v:-no}" || FAIL "PermitEmptyPasswords = $v -> 'no'"
  v="$(sshd_val x11forwarding)"
  [[ "${v,,}" == yes ]] && WARN "X11Forwarding = yes  -> deaktivieren, falls nicht benoetigt" || PASS "X11Forwarding = ${v:-no}"
  v="$(sshd_val port)"; INFO "SSH-Port: ${v:-22}"
else
  INFO "Kein SSH-Server (sshd) gefunden - uebersprungen."
fi

# --- 2) Firewall ---
sec "2) Firewall"
fw=0
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "Status: active"; then
  PASS "ufw aktiv"; fw=1
fi
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -qi running; then
  PASS "firewalld aktiv"; fw=1
fi
if [[ $fw -eq 0 ]] && command -v nft >/dev/null 2>&1 && [[ -n "$(nft list ruleset 2>/dev/null)" ]]; then
  PASS "nftables-Regelsatz vorhanden"; fw=1
fi
if [[ $fw -eq 0 ]] && command -v iptables >/dev/null 2>&1; then
  if [[ $(iptables -S 2>/dev/null | grep -c .) -gt 3 ]]; then PASS "iptables-Regeln vorhanden"; fw=1; fi
fi
[[ $fw -eq 0 ]] && FAIL "Keine aktive Firewall erkannt -> ufw/firewalld/nftables konfigurieren"

# --- 3) Automatische Sicherheitsupdates / ausstehende Updates ---
sec "3) Updates"
if command -v apt-get >/dev/null 2>&1; then
  if dpkg -l unattended-upgrades 2>/dev/null | grep -q '^ii'; then PASS "unattended-upgrades installiert"
  else WARN "unattended-upgrades nicht installiert -> automatische Sicherheitsupdates empfohlen"; fi
  if command -v apt >/dev/null 2>&1; then
    n="$(apt-get -s -o Debug::NoLocking=true upgrade 2>/dev/null | grep -ci '^Inst .*security')"
    [[ "${n:-0}" -gt 0 ]] && WARN "$n ausstehende Sicherheitsupdates (apt)" || INFO "Keine ausstehenden Security-Updates erkannt (apt)"
  fi
elif command -v dnf >/dev/null 2>&1; then
  if systemctl is-enabled dnf-automatic.timer >/dev/null 2>&1; then PASS "dnf-automatic.timer aktiv"
  else WARN "dnf-automatic nicht aktiv -> automatische Updates empfohlen"; fi
  n="$(dnf -q updateinfo list security 2>/dev/null | grep -c .)"
  [[ "${n:-0}" -gt 0 ]] && WARN "$n ausstehende Sicherheitsupdates (dnf)" || INFO "Keine ausstehenden Security-Updates erkannt (dnf)"
elif command -v pacman >/dev/null 2>&1; then
  INFO "Arch/pacman: Rolling Release - regelmaessig 'pacman -Syu' ausfuehren."
else
  INFO "Paketmanager nicht erkannt - Update-Pruefung uebersprungen."
fi

# --- 4) Konten & Passwoerter ---
sec "4) Benutzerkonten"
root_uids="$(awk -F: '($3==0){print $1}' /etc/passwd)"
[[ "$root_uids" == "root" ]] && PASS "Nur 'root' hat UID 0" || FAIL "Mehrere UID-0-Konten: $(echo $root_uids | tr '\n' ' ')"
if [[ -r /etc/shadow ]]; then
  empty="$(awk -F: '($2==""){print $1}' /etc/shadow)"
  [[ -z "$empty" ]] && PASS "Keine Konten mit leerem Passwort" || FAIL "Leeres Passwort: $(echo $empty | tr '\n' ' ')"
else
  INFO "/etc/shadow nicht lesbar (als root ausfuehren fuer Passwort-Check)"
fi

# --- 5) Kernel-/Netzwerk-sysctl ---
sec "5) Kernel- & Netzwerk-Haertung (sysctl)"
chk_sysctl() { # key  erwartet  empfehlung
  local cur; cur="$(sysctl -n "$1" 2>/dev/null)"
  if [[ -z "$cur" ]]; then INFO "$1 nicht verfuegbar"
  elif [[ "$cur" == "$2" ]]; then PASS "$1 = $cur"
  else WARN "$1 = $cur  -> empfohlen: $2 ($3)"; fi
}
chk_sysctl net.ipv4.tcp_syncookies 1 "SYN-Flood-Schutz"
chk_sysctl net.ipv4.conf.all.rp_filter 1 "Reverse-Path-Filter gegen Spoofing"
chk_sysctl net.ipv4.conf.all.accept_redirects 0 "ICMP-Redirects ignorieren"
chk_sysctl net.ipv4.conf.all.accept_source_route 0 "Source-Routing deaktivieren"
chk_sysctl kernel.randomize_va_space 2 "ASLR"
chk_sysctl kernel.kptr_restrict 1 "Kernel-Pointer verbergen"

# --- 6) Zeitsynchronisation ---
sec "6) Zeitsynchronisation"
if timedatectl show 2>/dev/null | grep -q 'NTPSynchronized=yes'; then PASS "Zeit via NTP synchronisiert"
elif systemctl is-active systemd-timesyncd >/dev/null 2>&1 || systemctl is-active chronyd >/dev/null 2>&1 || systemctl is-active ntpd >/dev/null 2>&1; then
  PASS "NTP-Dienst aktiv"
else WARN "Keine NTP-Synchronisation erkannt -> systemd-timesyncd/chrony aktivieren"; fi

# --- 7) Brute-Force-Schutz ---
sec "7) Brute-Force-Schutz"
if systemctl is-active fail2ban >/dev/null 2>&1; then PASS "fail2ban aktiv"
elif command -v fail2ban-client >/dev/null 2>&1; then WARN "fail2ban installiert, aber nicht aktiv"
else WARN "fail2ban nicht gefunden -> gegen SSH-Brute-Force empfohlen"; fi

# --- Zusammenfassung ---
sec "Zusammenfassung"
printf "  %sPASS: %d%s  ·  %sWARN: %d%s  ·  %sFAIL: %d%s\n" "$GRN" "$pass" "$RST" "$YEL" "$warn" "$RST" "$RED" "$fail" "$RST"
[[ $fail -gt 0 ]] && echo "  ${RED}${BLD}-> Kritische Punkte beheben.${RST}" || echo "  ${GRN}${BLD}-> Keine kritischen FAILs.${RST}"
echo "  Hinweis: Audit ersetzt keine vollstaendige Haertung (z.B. CIS-Benchmark)."

exit $(( fail > 0 ? 1 : 0 ))
