FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/admin-service ./cmd/admin-service

FROM gcr.io/distroless/base-debian12:nonroot
COPY --from=build /out/admin-service /admin-service
USER nonroot:nonroot
ENTRYPOINT ["/admin-service"]
