FROM golang:1.21-alpine as build
WORKDIR /app
COPY go.mod go.sum main.go .
RUN go build -v -o xbps-legacy-sign

FROM scratch
COPY --from=build /app/xbps-legacy-sign /xbps-legacy-sign
ENTRYPOINT [ "/xbps-legacy-sign" ]
CMD [ "-private-key", "/secrets/id_rsa", "-watch", "/pkgs" ]
