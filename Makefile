.PHONY: test fuzz fuzz-v2 fuzz-v3 mutation mutation-v2 mutation-v3

test:
	go test ./...

fuzz: fuzz-v2 fuzz-v3

fuzz-v2:
	go test ./v2 -run=^$$ -fuzz=FuzzParseDirectives -fuzztime=$${FUZZTIME:-10s}
	go test ./v2 -run=^$$ -fuzz=FuzzMiddleware -fuzztime=$${FUZZTIME:-10s}

fuzz-v3:
	go test ./v3 -run=^$$ -fuzz=FuzzParseDirectives -fuzztime=$${FUZZTIME:-10s}
	go test ./v3 -run=^$$ -fuzz=FuzzMiddleware -fuzztime=$${FUZZTIME:-10s}

mutation:
	./scripts/mutation-test.sh

mutation-v2:
	./scripts/mutation-test.sh ./v2

mutation-v3:
	./scripts/mutation-test.sh ./v3
