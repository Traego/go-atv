.PHONY: check test tidy

# gofmt, go vet and the tests with the race detector. Run before handing
# work over.
check:
	@out=$$(gofmt -l .) && if [ -n "$$out" ]; then echo "not gofmt'd:"; echo "$$out"; exit 1; fi
	@go vet ./...
	@go test -race ./...

test:
	@go test -race ./...

tidy:
	@go mod tidy
