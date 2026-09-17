.PHONY: build vet fmt test selfcheck

build:
	GOWORK=off go build ./...

vet:
	GOWORK=off go vet ./...

fmt:
	gofmt -l .

# selfcheck is this module's own credibility check: it builds both
# reference stubs, runs the full suite against each, and prints a
# safe-vs-vulnerable table with a per-test verdict. It exits non-zero if
# any test case fails to discriminate the two stubs (see selfcheck.sh's
# header comment and docs/security-test-suite.md's self-verification
# section for what "discriminate" means and why it is mandatory here).
selfcheck:
	./selfcheck.sh
