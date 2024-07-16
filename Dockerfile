FROM golang:1.21-alpine3.16 AS build
RUN apk --no-cache add gcc g++ make ca-certificates
WORKDIR /go/src/mo-service

COPY . .

RUN go build -o /go/bin/app ./cmd

FROM alpine:3.18
WORKDIR /usr/bin
COPY --from=build /go/bin .
CMD ["app"]