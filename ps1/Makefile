.PHONY: generate
generate:
	go generate ./...

.PHONY: build
build: generate
	go build ps1.go

.PHONY: start
start: build
	sudo ./ps1 $(port)
