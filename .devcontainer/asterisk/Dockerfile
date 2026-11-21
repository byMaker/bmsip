FROM alpine:3.20

RUN apk add --no-cache asterisk openssl \
    && mkdir -p /etc/asterisk/keys \
    && openssl req -x509 -newkey rsa:2048 -nodes \
       -keyout /etc/asterisk/keys/asterisk.key \
       -out /etc/asterisk/keys/asterisk.crt \
       -days 3650 \
       -subj "/CN=asterisk" \
       -addext "subjectAltName=DNS:asterisk,IP:127.0.0.1" \
    && chown -R asterisk:asterisk /etc/asterisk/keys \
    && chmod 600 /etc/asterisk/keys/asterisk.key

COPY modules.conf pjsip.conf extensions.conf rtp.conf logger.conf /etc/asterisk/

EXPOSE 5060/udp 5060/tcp 5061/tcp 10000-10020/udp

CMD ["asterisk", "-f", "-vvv"]

