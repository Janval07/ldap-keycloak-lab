FROM osixia/openldap:1.5.0

RUN echo "deb http://archive.debian.org/debian buster main" > /etc/apt/sources.list \
    && echo "deb http://archive.debian.org/debian-security buster/updates main" >> /etc/apt/sources.list \
    && apt-get update -o Acquire::Check-Valid-Until=false \
    && apt-get install -y --no-install-recommends fail2ban iptables iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /etc/fail2ban/jail.d/defaults-debian.conf

COPY fail2ban/jail.local /etc/fail2ban/jail.local
COPY fail2ban/ldap-flood.conf /etc/fail2ban/filter.d/ldap-flood.conf
COPY entrypoint.sh /custom-entrypoint.sh
RUN chmod +x /custom-entrypoint.sh

ENTRYPOINT ["/custom-entrypoint.sh"]