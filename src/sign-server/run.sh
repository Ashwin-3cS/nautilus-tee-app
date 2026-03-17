#!/bin/sh
set -e

export LD_LIBRARY_PATH=/lib:$LD_LIBRARY_PATH

# Setup loopback networking
busybox ip addr add 127.0.0.1/32 dev lo
busybox ip link set dev lo up
echo "127.0.0.1   localhost" > /etc/hosts

# Set enclave mode
export ENCLAVE_MODE=true
echo "Enclave mode enabled"

# Expose sign-server on VSOCK port 4000
socat VSOCK-LISTEN:4000,reuseaddr,fork TCP:localhost:4000 &

echo "Starting sign-server on port 4000..."
/sign_server > /tmp/server.log 2>&1 &
SERVER_PID=$!

echo "sign-server started: PID $SERVER_PID (port 4000)"

# Forward logs to host via VSOCK port 5000
(tail -f /tmp/server.log 2>/dev/null | socat - VSOCK-CONNECT:3:5000 2>/dev/null) &

wait $SERVER_PID
