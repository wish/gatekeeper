FROM golang:1.10
WORKDIR /go/src/github.com/wish/gatekeeper/
COPY . /go/src/github.com/wish/gatekeeper/
RUN curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh
RUN dep ensure
RUN make
