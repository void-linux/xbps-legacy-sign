FROM ghcr.io/void-linux/void-musl:latest as build
WORKDIR /app
COPY go.mod go.sum main.go .
RUN xbps-install -Suy xbps && \
	xbps-install -y git go && \
	go build -v -o xbps-legacy-sign

ENTRYPOINT [ "/app/xbps-legacy-sign" ]
CMD [ "-private-key", "/secrets/id_rsa", "-watch", "/pkgs" ]
