# ghcr.io/olljanat-ai/containerizer-pickup-relay: drains an SMTP pickup folder (README.md).
# Static Go binary on distroless static: no shell, no package manager, non-root (65532), read-only root.
FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN go test ./... && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/pickup-relay .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/pickup-relay /pickup-relay
USER 65532:65532
ENV PICKUP_DIR=/pickup
ENTRYPOINT ["/pickup-relay"]
