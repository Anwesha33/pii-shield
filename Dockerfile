# Build stage: compile a static binary so the runtime image needs no toolchain.
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/pii-shield ./cmd/proxy

# Runtime stage: distroless-style minimal image. No shell, no package manager,
# nothing for an attacker to pivot into on a box that by design handles
# sensitive values in memory.
FROM gcr.io/distroless/static-debian12
COPY --from=build /out/pii-shield /pii-shield
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/pii-shield"]
