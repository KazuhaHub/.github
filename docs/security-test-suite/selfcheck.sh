#!/usr/bin/env bash
# selfcheck.sh — the suite's own credibility check.
#
# Every test case in this module makes a claim: "I catch a real gap." The
# only way to back that claim with evidence, short of a live target project,
# is to run the whole suite against two known-shape reference servers and
# confirm each test behaves the way its claim requires:
#
#   - reference/safe (a correct implementation)        -> the test must PASS
#   - reference/vulnerable (the same shape, holes left) -> the test must FAIL
#
# A test that PASSES against both stubs asserted nothing — it is dead
# weight that manufactures false confidence — and this script's exit code
# reflects that: it fails loudly instead of a human having to notice.
#
# Two documented exceptions are not required to discriminate, and are
# recognized purely by a name-suffix convention so this script never has to
# guess intent:
#   *_VersionGate     — a manual "check the pinned library version" note,
#                        not an automated exploit; expected to PASS on BOTH
#                        stubs (see saml_test.go's package doc).
#   *_NeedsWhiteBox    — a documented gap this suite's black-box HTTP
#                        surface cannot force a stub to distinguish yet;
#                        expected to SKIP on BOTH stubs (see audit_test.go).
#
# Usage:
#   ./selfcheck.sh            # build, run, print the table, verdict via exit code
#   ./selfcheck.sh --keep-logs  # also leave the raw go-test logs behind for inspection
#
# Exit code is 0 only if every test case's safe/vulnerable pair matches its
# expected pattern above. Non-zero and the printed table both say why.
set -u -o pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

KEEP_LOGS=0
if [[ "${1:-}" == "--keep-logs" ]]; then
	KEEP_LOGS=1
fi

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/sectest-selfcheck.XXXXXX")"
SAFE_PID=""
VULN_PID=""
SAFE_TRUSTED_PID=""

cleanup() {
	[[ -n "$SAFE_PID" ]] && kill "$SAFE_PID" >/dev/null 2>&1
	[[ -n "$VULN_PID" ]] && kill "$VULN_PID" >/dev/null 2>&1
	[[ -n "$SAFE_TRUSTED_PID" ]] && kill "$SAFE_TRUSTED_PID" >/dev/null 2>&1
	if [[ "$KEEP_LOGS" -eq 1 ]]; then
		echo "selfcheck: logs kept at $WORKDIR" >&2
	else
		rm -rf "$WORKDIR"
	fi
}
trap cleanup EXIT

fail_hard() {
	echo "selfcheck: $*" >&2
	exit 2
}

# Fixtures are generated, not committed: a private key in a public repository is
# permanent and trips secret scanning, even a provably test-only one. Regenerate
# whenever they are missing so a fresh clone works with no extra setup step.
if [ ! -f fixtures/idp-test-key.pem ] || [ ! -f fixtures/idp-metadata.xml ]; then
  echo "== selfcheck: generating test fixtures (go run ./fixtures) =="
  go run ./fixtures
fi

echo "== selfcheck: building reference stubs and test binary ==" >&2
GOWORK=off go build -o "$WORKDIR/safe" ./reference/safe || fail_hard "reference/safe failed to build"
GOWORK=off go build -o "$WORKDIR/vulnerable" ./reference/vulnerable || fail_hard "reference/vulnerable failed to build"
GOWORK=off go vet ./... || fail_hard "go vet failed"
if [[ -n "$(gofmt -l .)" ]]; then
	fail_hard "gofmt -l reports unformatted files: $(gofmt -l .)"
fi

# -addr 127.0.0.1:0 asks the OS for a free port instead of a port this
# script guesses at — an earlier draft of this workflow used fixed ports
# and got silently fooled by a stale server left running from a previous
# session that had already bound them (go's listen failure went to a log
# file nobody was watching, while an old process with dirty in-memory state
# kept answering requests). Never repeat that: always read the port back
# from what the process itself reports it bound.
start_stub() {
	local bin="$1" logfile="$2"
	"$bin" -addr 127.0.0.1:0 >"$logfile" 2>&1 &
	local pid=$!
	local addr=""
	for _ in $(seq 1 50); do
		if ! kill -0 "$pid" >/dev/null 2>&1; then
			cat "$logfile" >&2
			fail_hard "$bin exited before it started listening"
		fi
		addr="$(sed -n 's#.*listening on http://\([^ ]*\).*#\1#p' "$logfile" | head -n1)"
		[[ -n "$addr" ]] && break
		sleep 0.1
	done
	[[ -n "$addr" ]] || fail_hard "$bin never printed its listen address (see $logfile)"
	if ! curl -s -o /dev/null -m 5 "http://$addr/healthz"; then
		fail_hard "$bin at $addr did not answer GET /healthz"
	fi
	echo "$pid $addr"
}

echo "== selfcheck: starting reference/safe ==" >&2
read -r SAFE_PID SAFE_ADDR < <(start_stub "$WORKDIR/safe" "$WORKDIR/safe.log")
echo "  reference/safe      pid=$SAFE_PID  http://$SAFE_ADDR" >&2

echo "== selfcheck: starting reference/vulnerable ==" >&2
read -r VULN_PID VULN_ADDR < <(start_stub "$WORKDIR/vulnerable" "$WORKDIR/vulnerable.log")
echo "  reference/vulnerable pid=$VULN_PID  http://$VULN_ADDR" >&2

# A THIRD instance, safe binary but configured to TRUST the loopback address
# this script's `go test` process actually connects from — the opposite of
# reference/safe's default -trusted-proxies=203.0.113.0/24 (see main.go and
# TestRateLimit_XFFTrustBoundary's doc comment on why the default must NOT
# trust loopback). This exists only so
# TestRateLimit_TrustedProxyXFFHonoredGate (design doc 4.5's "正例" row) has
# something to verify against; every other test in this suite talks to
# SAFE_ADDR/VULN_ADDR above, never to this one.
echo "== selfcheck: starting reference/safe (loopback-trusted, for the 4.5 positive-path gate) ==" >&2
read -r SAFE_TRUSTED_PID SAFE_TRUSTED_ADDR < <(
	"$WORKDIR/safe" -addr 127.0.0.1:0 -trusted-proxies=127.0.0.1/32,::1/128 >"$WORKDIR/safe_trusted.log" 2>&1 &
	pid=$!
	addr=""
	for _ in $(seq 1 50); do
		if ! kill -0 "$pid" >/dev/null 2>&1; then
			cat "$WORKDIR/safe_trusted.log" >&2
			fail_hard "reference/safe (loopback-trusted) exited before it started listening"
		fi
		addr="$(sed -n 's#.*listening on http://\([^ ]*\).*#\1#p' "$WORKDIR/safe_trusted.log" | head -n1)"
		[[ -n "$addr" ]] && break
		sleep 0.1
	done
	[[ -n "$addr" ]] || fail_hard "reference/safe (loopback-trusted) never printed its listen address"
	echo "$pid $addr"
)
echo "  reference/safe (loopback-trusted) pid=$SAFE_TRUSTED_PID  http://$SAFE_TRUSTED_ADDR" >&2

echo "== selfcheck: running full suite against reference/safe ==" >&2
SECTEST_BASE_URL="http://$SAFE_ADDR" SECTEST_TRUSTED_PROXY_BASE_URL="http://$SAFE_TRUSTED_ADDR" \
	GOWORK=off go test ./... -v -count=1 -timeout 300s \
	>"$WORKDIR/safe_run.log" 2>&1
SAFE_EXIT=$?

echo "== selfcheck: running full suite against reference/vulnerable ==" >&2
# reference/vulnerable has no trusted-proxy CIDR concept at all — it trusts
# X-Forwarded-For from every peer unconditionally (see its clientIP doc
# comment) — so pointing the positive-path gate at the SAME vulnerable
# instance is sufficient: it trivially satisfies "a trusted peer's XFF is
# honored" for the same reason it fails every negative case above.
SECTEST_BASE_URL="http://$VULN_ADDR" SECTEST_TRUSTED_PROXY_BASE_URL="http://$VULN_ADDR" \
	GOWORK=off go test ./... -v -count=1 -timeout 300s \
	>"$WORKDIR/vuln_run.log" 2>&1
VULN_EXIT=$?

# Extract top-level "--- PASS/FAIL/SKIP: TestName" lines only (not
# subtests, which are indented "--- PASS: Test/Sub" — a leading tab marks
# those and this pattern deliberately excludes it) into "Name Result" pairs.
extract_results() {
	grep -E '^--- (PASS|FAIL|SKIP): ' "$1" \
		| sed -E 's/^--- (PASS|FAIL|SKIP): ([A-Za-z0-9_]+).*/\2 \1/'
}

extract_results "$WORKDIR/safe_run.log" | sort >"$WORKDIR/safe_results.txt"
extract_results "$WORKDIR/vuln_run.log" | sort >"$WORKDIR/vuln_results.txt"

SAFE_NAMES="$(cut -d' ' -f1 "$WORKDIR/safe_results.txt" | sort -u)"
VULN_NAMES="$(cut -d' ' -f1 "$WORKDIR/vuln_results.txt" | sort -u)"
ALL_NAMES="$(printf '%s\n%s\n' "$SAFE_NAMES" "$VULN_NAMES" | sort -u)"

if [[ "$SAFE_NAMES" != "$VULN_NAMES" ]]; then
	echo "selfcheck: WARNING — the safe and vulnerable runs reported a different set of top-level tests; see raw logs" >&2
fi

result_for() { # $1=file $2=name
	awk -v n="$2" '$1==n{print $2; found=1} END{if(!found) print "MISSING"}' "$1"
}

overall_ok=1
printf '| %-52s | %-11s | %-11s | %s |\n' "Test case" "safe" "vulnerable" "Effective?"
printf '|%s|%s|%s|%s|\n' "$(printf -- '-%.0s' $(seq 1 54))" "$(printf -- '-%.0s' $(seq 1 13))" "$(printf -- '-%.0s' $(seq 1 13))" "$(printf -- '-%.0s' $(seq 1 12))"

rows=()
while IFS= read -r name; do
	[[ -z "$name" ]] && continue
	s="$(result_for "$WORKDIR/safe_results.txt" "$name")"
	v="$(result_for "$WORKDIR/vuln_results.txt" "$name")"

	verdict=""
	ok=1
	case "$name" in
	*VersionGate)
		# Expected: informational, PASS on both — never skips, never
		# distinguishes the stubs by design (see saml_test.go).
		if [[ "$s" == "PASS" && "$v" == "PASS" ]]; then
			verdict="gate (manual check, by design)"
		else
			verdict="INVALID — expected PASS/PASS for a version gate, got $s/$v"
			ok=0
		fi
		;;
	*Gate)
		# Broader "Gate" suffix (checked after the more specific
		# *VersionGate above): also expected PASS on both, but for a
		# different documented reason per test — e.g.
		# TestRateLimit_TrustedProxyXFFHonoredGate (ratelimit_test.go)
		# inherently also passes against reference/vulnerable, since a
		# target that trusts X-Forwarded-For from EVERY peer necessarily
		# also honors it from a trusted one — that is not this test's job
		# to catch (TestRateLimit_XFFTrustBoundary's negative cases do).
		if [[ "$s" == "PASS" && "$v" == "PASS" ]]; then
			verdict="gate (config-dependent check, by design)"
		else
			verdict="INVALID — expected PASS/PASS for a *Gate case, got $s/$v"
			ok=0
		fi
		;;
	*_NeedsWhiteBox)
		# Expected: SKIP on both — a documented, reasoned gap this suite's
		# black-box HTTP surface cannot force yet (see audit_test.go).
		if [[ "$s" == "SKIP" && "$v" == "SKIP" ]]; then
			verdict="gate (needs white-box, by design)"
		else
			verdict="INVALID — expected SKIP/SKIP for a white-box gate, got $s/$v"
			ok=0
		fi
		;;
	*_SelfTest)
		# Expected: informational, PASS on both — a self-test of
		# internal/authenticator's own encoding/signing correctness
		# (verified against a real, in-process go-webauthn/webauthn
		# relying party the test itself constructs; see
		# authenticator_test.go), not a black-box discrimination case
		# against reference/safe vs reference/vulnerable. It never talks
		# to SECTEST_BASE_URL at all, so it is expected to behave
		# identically regardless of which stub this run points at.
		if [[ "$s" == "PASS" && "$v" == "PASS" ]]; then
			verdict="gate (authenticator package self-test, by design)"
		else
			verdict="INVALID — expected PASS/PASS for a *_SelfTest case, got $s/$v"
			ok=0
		fi
		;;
	*)
		if [[ "$s" == "PASS" && "$v" == "FAIL" ]]; then
			verdict="yes — discriminates"
		elif [[ "$s" == "PASS" && "$v" == "PASS" ]]; then
			verdict="NO — passes both, tests nothing"
			ok=0
		elif [[ "$s" == "FAIL" ]]; then
			verdict="NO — fails against safe (broken test or broken stub)"
			ok=0
		elif [[ "$v" == "SKIP" || "$s" == "SKIP" ]]; then
			verdict="NO — unexpected skip outside a documented gate"
			ok=0
		else
			verdict="NO — unexpected result pair ($s/$v)"
			ok=0
		fi
		;;
	esac

	[[ "$ok" -eq 0 ]] && overall_ok=0
	printf '| %-52s | %-11s | %-11s | %s |\n' "$name" "$s" "$v" "$verdict"
done <<<"$ALL_NAMES"

echo >&2
if [[ "$SAFE_EXIT" -ne 0 ]]; then
	echo "selfcheck: FAIL — the suite did not exit 0 against reference/safe (some non-gate test failed; see table and $WORKDIR/safe_run.log)" >&2
	overall_ok=0
fi
if [[ "$VULN_EXIT" -eq 0 ]]; then
	echo "selfcheck: FAIL — the suite exited 0 against reference/vulnerable; it must report at least one failure per attack area, see the design doc's self-verification section" >&2
	overall_ok=0
fi

if [[ "$overall_ok" -eq 1 ]]; then
	echo "selfcheck: PASS — every test case discriminates safe from vulnerable as required (or is a documented, by-design exception)." >&2
	exit 0
else
	echo "selfcheck: FAIL — one or more test cases above do not discriminate; fix the assertion or the vulnerable stub's missing gap before trusting this suite." >&2
	exit 1
fi
