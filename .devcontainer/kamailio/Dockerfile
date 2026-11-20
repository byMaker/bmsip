FROM alpine:3.20

RUN apk add --no-cache kamailio kamailio-db \
    && mkdir -p /etc/kamailio /var/run/kamailio

COPY kamailio.cfg /etc/kamailio/kamailio.cfg

EXPOSE 5060/udp

CMD ["kamailio", "-DD", "-E", "-f", "/etc/kamailio/kamailio.cfg"]
