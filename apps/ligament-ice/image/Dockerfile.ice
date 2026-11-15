FROM coturn/coturn:4.6.2-alpine

USER root

COPY turnserver.conf /usr/local/share/ligament-ice/turnserver.conf
COPY entrypoint-ice.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && mkdir -p /etc/coturn /etc/coturn/certs

EXPOSE 443/tcp 443/udp 3478/tcp 3478/udp 5349/tcp 5349/udp

ENTRYPOINT ["/entrypoint.sh"]
