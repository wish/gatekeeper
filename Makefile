default:
	@GOOS=linux CGO_ENABLED=0 packr build -o ${GOPATH}/bin/gatekeeper github.com/wish/gatekeeper
