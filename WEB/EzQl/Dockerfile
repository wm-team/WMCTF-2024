FROM openjdk:8
USER root
ENV FLAG WMCTF{e6d5457d4398b8c544ac677f4c224514}
COPY ./WEB /opt/app/
RUN chmod +x /opt/app/start.sh && \
	chmod +x /opt/app/flag.sh
WORKDIR /opt/app
CMD ["./start.sh"]
