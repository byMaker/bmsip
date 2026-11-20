FROM alpine:3.20

RUN apk add --no-cache freeswitch \
    && mkdir -p /etc/freeswitch /var/log/freeswitch /var/run/freeswitch

COPY freeswitch.xml /etc/freeswitch/freeswitch.xml

EXPOSE 5060/udp 16384-16404/udp

CMD ["freeswitch", "-nf", "-nonat", "-nosql"]

