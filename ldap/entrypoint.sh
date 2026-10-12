#!/bin/bash
set -e

mkdir -p /var/log/openldap /var/run/fail2ban
rm -f /var/run/fail2ban/fail2ban.sock /var/run/fail2ban/fail2ban.pid
touch /var/log/openldap/slapd.log /var/log/fail2ban.log

# Arranca OpenLDAP con el entrypoint original de la imagen (bootstrap + TLS).
# Cada línea se prefija con una fecha real, porque el identificador hexadecimal
# propio de slapd no es una fecha que fail2ban pueda interpretar, y sin fecha
# reconocible la descarta en vez de contarla.
( /container/tool/run "$@" 2>&1 | while IFS= read -r line; do
    printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)" "$line"
done >> /var/log/openldap/slapd.log ) &

sleep 10
fail2ban-client -x start

echo "[openldap] slapd + fail2ban corriendo. Siguiendo el log de fail2ban..."
exec tail -F /var/log/fail2ban.log