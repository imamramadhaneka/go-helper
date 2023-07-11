.PHONY: cover test

PACKAGES = $(shell go list ./... | grep -v -e _examples)

cover:
	@echo ">> calculate coverage"
	@go test ./...  -cover -coverprofile=coverage.txt -covermode=set -coverpkg=$(PACKAGES)
	@go tool cover -func=coverage.txt

test:
	$(foreach pkg, $(PACKAGES),\
	go test $(pkg);)