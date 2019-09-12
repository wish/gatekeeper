FROM golang:1.10 as gatekeeper
WORKDIR /go/src/github.com/wish/gatekeeper/
COPY . /go/src/github.com/wish/gatekeeper/
RUN curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh
RUN dep ensure
RUN go get -u github.com/gobuffalo/packr/...
RUN make

FROM quay.io/wish/jsonnet-builder:v0.13.0 as jsonnet

FROM alpine:latest
RUN apk add --no-cache make python git libstdc++ gcompat
COPY --from=gatekeeper /go/bin/gatekeeper /usr/local/bin
COPY --from=jsonnet /bin/jsonnet /usr/local/bin/jsonnet
COPY --from=jsonnet /bin/jsonnetfmt /usr/local/bin/jsonnetfmt
