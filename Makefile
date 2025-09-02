GO_TEST := $(shell command -v richgo >/dev/null 2>&1 && echo richgo || echo go)

.PHONY: clean
clean:
	@echo "Cleaning build artifacts and test cache..."
	go clean -testcache

.PHONY: test
test:
	@echo "Running tests with $(GO_TEST)"
	$(GO_TEST) test ./... -v

.PHONY: integration
integration:
	$(GO_TEST) test ./test -v -tags=integration
