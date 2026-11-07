FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install --no-install-recommends --yes ca-certificates tor \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/lib/tor \
    && chown -R debian-tor:debian-tor /var/lib/tor
COPY torrc /etc/tor/torrc
USER debian-tor
EXPOSE 9050 9051
ENTRYPOINT ["tor", "-f", "/etc/tor/torrc"]
