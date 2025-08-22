.PHONY: test
test:
	go test ./... -v

.PHONY: integration
integration:
	go test ./test -v -tags=integration
