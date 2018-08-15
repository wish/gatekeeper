FROM golang:1.10 as gatekeeper
WORKDIR /go/src/github.com/wish/gatekeeper/
COPY . /go/src/github.com/wish/gatekeeper/
RUN curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh
RUN dep ensure
RUN go get -u github.com/gobuffalo/packr/...
RUN make

FROM sparkprime/jsonnet as jsonnet

FROM alpine:latest
RUN apk add --no-cache make python git libstdc++ 
COPY --from=gatekeeper /go/bin/gatekeeper /usr/local/bin
COPY --from=jsonnet /usr/local/bin/jsonnet /usr/local/bin/jsonnet
