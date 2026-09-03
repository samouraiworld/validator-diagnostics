FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/portal ./cmd/portal
# rescore ships alongside the portal rather than in an image of its own:
# it reads the same /data volume, and the only way to reach that volume
# with the right uid and the right paths is a container built from this
# same stack. Run it with
# `docker compose run --rm --no-deps --entrypoint rescore portal ...`.
RUN CGO_ENABLED=0 go build -o /out/rescore ./cmd/rescore

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/portal /usr/local/bin/portal
COPY --from=build /out/rescore /usr/local/bin/rescore
EXPOSE 8888
ENTRYPOINT ["portal"]
