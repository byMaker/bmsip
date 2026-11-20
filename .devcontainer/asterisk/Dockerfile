FROM alpine:3.20

RUN apk add --no-cache asterisk

COPY modules.conf pjsip.conf extensions.conf rtp.conf logger.conf /etc/asterisk/

EXPOSE 5060/udp 10000-10020/udp

CMD ["asterisk", "-f", "-vvv"]
