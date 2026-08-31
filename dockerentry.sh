#!/bin/sh
#DEPRECATED, see https://gokapi.readthedocs.io/en/latest/setup.html#migration-from-docker-nonroot-to-docker-user

# Restrictive umask: gokapi creates the sqlite DB (session tokens, API keys,
# hashed passwords, client IPs), its -wal/-shm siblings, and the encrypted
# upload blobs directly, with no explicit chmod call of its own. Without
# this, new files inherit the process's default umask (022), landing at
# world-readable 644 -- letting any local user on the host read session
# tokens straight out of the database. 0077 makes every file gokapi creates
# from here on 600 (700 for directories) at the moment of creation.
umask 0077

if [ "$DOCKER_NONROOT" = "true" ]; then
	# TODO for the next major upgrade version:
	# 	- Remove this code block and leave only exec /app/gokapi "@"
	# 	- Remove gokapi user / group creation in Dockerfile
	# 	- Remove su-exec installation from the Dockerfile
	echo "Setting permissions" && \
	chown -R gokapi:gokapi /app && \
	chmod -R 700 /app && \
	echo "Starting application" && \
	exec su-exec gokapi:gokapi /app/gokapi "$@"
else
	exec /app/gokapi "$@"
fi

