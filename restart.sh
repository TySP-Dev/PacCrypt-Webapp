#!/bin/bash
sleep 2

# Save current process PID
PID=$1

# Gracefully stop the current server
kill "$PID"

# Wait until it exits
while kill -0 "$PID" 2>/dev/null; do
    sleep 0.5
done

# Restart with the same interpreter and script
export PRODUCTION=true
exec "$2" "$3"
