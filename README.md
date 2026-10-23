# tools

Kleine Sammlung von Admin- und Security-Hilfsskripten.

## php-patch-check.sh

Prüft, ob die installierte PHP-Version gegen **PHP2Shell**
(CVE-2026-109618 / CVE-2026-109619, CVSS 9.2) gepatcht ist.

```bash
bash php-patch-check.sh
```

Nur lesend – verändert nichts am System. Auf dem zu prüfenden Server ausführen.

**Exit-Codes:** `0` = OK · `1` = verwundbar · `2` = unklar (für Monitoring/CI nutzbar).

Gepatchte Mindestversionen: `8.5.12` / `8.4.27` / `8.3.36` / `8.2.35`.
PHP 7.4–8.1 haben kein offizielles Patch-Release → isolieren oder migrieren.

> Hinweis: Das Skript prüft CLI-Binaries. Maßgeblich für die Lücke ist die
> Version, die der Webserver ausführt (meist PHP-FPM) – diese ggf. separat
> mit `php-fpm -v` bzw. `systemctl status 'php*-fpm'` bestätigen.
