#!/bin/sh
# Runs the full test baseline.
#
# The three tag combinations run at the same time, which takes two kinds of isolation. Every
# package writes its fixtures into a "test" directory next to its own sources, so each combination
# gets a copy of the tree to itself. The tests also bind real TCP ports, so each copy is handed a
# GOKAPI_TEST_PORT_OFFSET that moves its whole block of test ports (see
# internal/test/testconfiguration) clear of the other two.
set -e
cd "$(dirname "$0")"
sourceDir=$(pwd)

# Set GOKAPI_TEST_POSTGRES_URL to include the Postgres provider. Without it the
# share-recipient tests cover only SQLite and Redis.

runDir=$(mktemp -d)
trap 'rm -rf "$runDir"' EXIT INT TERM

# runTests runs one tag combination in a copy of the tree and writes its report to
# $runDir/$2.result, so that the three reports can be printed in a fixed order afterwards. It
# returns non-zero if that combination had a failing package.
runTests() {
	tags=$1
	offset=$2
	workDir="$runDir/$offset"
	mkdir "$workDir"
	tar -cf - --exclude=./.git -C "$sourceDir" . | tar -xf - -C "$workDir"
	cd "$workDir"
	output=$(GOKAPI_TEST_PORT_OFFSET="$offset" go test ./... -parallel 8 -count=1 --tags="$tags" 2>&1) || true
	passed=$(printf '%s\n' "$output" | grep -c '^ok ' || true)
	failed=$(printf '%s\n' "$output" | grep -c '^FAIL' || true)
	{
		printf '%-26s ok=%s fail=%s\n' "$tags" "$passed" "$failed"
		if [ "$failed" != "0" ]; then
			printf '%s\n' "$output" | grep -E '^--- FAIL|^FAIL' | head -20
		fi
	} >"$workDir.result"
	if [ "$failed" != "0" ]; then
		return 1
	fi
	return 0
}

runTests "test,noaws" 0 &
pidNoaws=$!
runTests "test,awsmock" 20 &
pidAwsmock=$!
runTests "test,noaws,integration" 40 &
pidIntegration=$!

exitCode=0
wait $pidNoaws || exitCode=1
wait $pidAwsmock || exitCode=1
wait $pidIntegration || exitCode=1

cat "$runDir/0.result" "$runDir/20.result" "$runDir/40.result"
exit $exitCode
