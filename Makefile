default:
	@GOOS=linux CGO_ENABLED=0 go build -o ${GOPATH}/bin/gatekeeper github.com/wish/gatekeeper
