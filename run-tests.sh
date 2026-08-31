#!/bin/sh
# Runs the full test baseline with the deployment container stopped, and always
# brings it back.
#
# The configuration/setup tests bind port 53842, which the running "filedrop"
# container already holds, so leaving it up produces spurious failures
# (README gotcha 1). Stopping it by hand is easy; forgetting to restart it
# afterwards is easier, and the symptom is a dead UI with 502s on /auth/token.
# The trap is the whole point of this script.
set -e
cd "$(dirname "$0")"

WAS_RUNNING=0
if [ "$(docker inspect -f '{{.State.Running}}' filedrop 2>/dev/null)" = "true" ]; then
	WAS_RUNNING=1
fi

restore() {
	if [ "$WAS_RUNNING" = "1" ]; then
		echo "Restarting the filedrop container"
		docker start filedrop >/dev/null 2>&1 || true
	fi
}
trap restore EXIT INT TERM

if [ "$WAS_RUNNING" = "1" ]; then
	echo "Stopping the filedrop container so port 53842 is free"
	docker stop filedrop >/dev/null
fi

# Set GOKAPI_TEST_POSTGRES_URL to include the Postgres provider. Without it the
# share-recipient tests cover only SQLite and Redis.
for TAGS in "test,noaws" "test,awsmock" "test,noaws,integration"; do
	printf '%-26s ' "$TAGS"
	OUTPUT=$(go test ./... -parallel 8 -count=1 --tags="$TAGS" 2>&1) || true
	PASSED=$(printf '%s\n' "$OUTPUT" | grep -c '^ok ' || true)
	FAILED=$(printf '%s\n' "$OUTPUT" | grep -c '^FAIL' || true)
	echo "ok=$PASSED fail=$FAILED"
	if [ "$FAILED" != "0" ]; then
		printf '%s\n' "$OUTPUT" | grep -E '^--- FAIL|^FAIL' | head -20
	fi
done
