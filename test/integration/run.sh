#!/bin/sh
# Copyright (c) 2026 gx14ac
# SPDX-License-Identifier: Apache-2.0

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVER_DIR="$SCRIPT_DIR/server"
ROOT_DIR="$SCRIPT_DIR/../.."

echo "Building Go gRPC test server..."
(cd "$SERVER_DIR" && go build -o server .)

echo "Starting server..."
"$SERVER_DIR/server" > /tmp/grpc-test-server.out 2>&1 &
SERVER_PID=$!

cleanup() {
    kill $SERVER_PID 2>/dev/null
    wait $SERVER_PID 2>/dev/null
    rm -f "$SERVER_DIR/server" /tmp/grpc-test-server.out
}
trap cleanup EXIT

# Wait for server to print READY (up to 10 seconds)
for i in $(seq 1 100); do
    if grep -q "READY:" /tmp/grpc-test-server.out 2>/dev/null; then
        break
    fi
    if ! kill -0 $SERVER_PID 2>/dev/null; then
        echo "ERROR: server exited unexpectedly"
        cat /tmp/grpc-test-server.out
        exit 1
    fi
    sleep 0.1
done

if ! grep -q "READY:" /tmp/grpc-test-server.out 2>/dev/null; then
    echo "ERROR: server did not become ready within 10s"
    cat /tmp/grpc-test-server.out
    exit 1
fi

echo "Running integration tests..."
(cd "$ROOT_DIR" && zig build integration-test)

echo "All integration tests passed!"
