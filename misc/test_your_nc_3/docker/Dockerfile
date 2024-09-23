FROM ubuntu:18.04

RUN apt update && apt upgrade -y
RUN apt install -y python socat

COPY app.py /bin/114sh
COPY start.sh /app/start.sh
COPY flag /flag

RUN chown -R root:root /app && \
    chmod -R 755 /app && chmod 000 /flag && chown root:root /bin/114sh && chmod 755 /bin/114sh

EXPOSE 9999
CMD ["bash","/app/start.sh"]