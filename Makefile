.DEFAULT_GOAL := help
.PHONY: help fmt fmt-check lint vet test test-race build web tidy check clean deploy

GO      ?= go
BIN     ?= ntc
PKGS    ?= ./source/...

help: ## Show this help
	@grep -hE '^[a-z-]+:.*##' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN{FS=":.*## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

fmt: ## Format all Go code
	$(GO) fmt $(PKGS)
	gofmt -s -w source/

lint: ## Run golangci-lint (includes the depguard architecture rule)
	golangci-lint run $(PKGS)

vet: ## Run go vet
	$(GO) vet $(PKGS)

test: ## Run tests
	$(GO) test $(PKGS)

test-race: ## Run tests with the race detector
	$(GO) test -race $(PKGS)

tidy: ## Tidy go.mod/go.sum
	$(GO) mod tidy

build: ## Build the backend binary (host platform)
	$(GO) build -o $(BIN) ./source

web: ## Build the Svelte frontend into dist/
	cd web && npm ci && npm run build

check: fmt-check vet lint test-race ## Everything CI runs

fmt-check: ## Fail if any file is not gofmt'ed
	@out=$$(gofmt -l source/); \
	if [ -n "$$out" ]; then echo "not gofmt'ed:"; echo "$$out"; exit 1; fi

clean: ## Remove build artifacts
	rm -f $(BIN) ntc_bin *.bpf.o

deploy: ## Passthrough to scripts/deploy.sh, e.g. make deploy ARGS=rpi-build
	./scripts/deploy.sh $(ARGS)