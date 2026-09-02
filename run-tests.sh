#!/bin/sh
# Runs the full test baseline.
#
# The configuration/setup tests bind port 53842 for real, so nothing else may
# hold it. The local dev container publishes the backend on 8080 and keeps
# 53842 to itself inside the container, which is why the tests and the running
# stack no longer collide.
set -e
cd "$(dirname "$0")"

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
